//! Подключение, отключение, смена профиля.

use iced::Task;
use penguin_ipc::schema::{Event, LogLevel, Request, Response};

use crate::app::App;
use crate::app::message::{HomeMessage, IpcMessage, Message, ServiceOutcome};
use crate::app::update::request;

/// Сколько ждать, пока служба опустит тоннель и остановится.
const SHUTDOWN_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Сколько всего ждать, пока служба выйдет на связь (у попытки свой предел).
const SERVICE_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Пауза между попытками.
const SERVICE_WAIT_STEP: std::time::Duration = std::time::Duration::from_millis(250);

/// Разбирает всё, что пришло от демона.
pub fn handle(app: &mut App, message: IpcMessage) -> Task<Message> {
    match message {
        IpcMessage::Response(response) => handle_response(app, *response),
        IpcMessage::Event(event) => handle_event(app, *event),
        IpcMessage::Disconnected(reason) => {
            // Пустая причина — подписка подключилась.
            if reason.is_empty() {
                let connection = &mut app.state_mut().connection;
                connection.online = true;
                connection.starting = false;
                connection.error = None;
                return crate::app::update::request_initial_state();
            }
            app.state_mut().connection.mark_offline(reason);
            Task::none()
        }
    }
}

fn handle_response(app: &mut App, response: Response) -> Task<Message> {
    let state = app.state_mut();

    match response {
        Response::Ok | Response::Pong { .. } => {}
        Response::Status(status) => state.connection.apply_status(&status),
        Response::Config(config) => {
            state.config = *config;
            state.saved = state.config.clone();
            state.dirty = false;
        }
        Response::Explanation(explanation) => {
            state.split_tunnel.probe_result = Some(*explanation);
        }
        Response::Processes { apps } => state.split_tunnel.running_apps = apps,
        Response::Probes { results } => {
            state.servers.probing = false;
            state.servers.latencies = results
                .into_iter()
                .map(|row| (row.profile, row.rtt_millis))
                .collect();
        }
        // В журнал, не в модальное окно: половина ошибок приходит фоном.
        Response::Error { message, .. } => state.connection.push_log(LogLevel::Error, message),
    }
    Task::none()
}

fn handle_event(app: &mut App, event: Event) -> Task<Message> {
    let connection = &mut app.state_mut().connection;

    match event {
        Event::State { state: tunnel } => {
            connection.set_tunnel(tunnel);
            connection.online = true;
        }
        Event::Throughput {
            rate,
            total,
            connections,
        } => connection.apply_throughput(rate, total, connections),
        Event::Log { level, message } => connection.push_log(level, message),
        Event::Decision {
            target,
            process,
            decision,
            rule,
        } => {
            // Правило дописывается, только если сработало: «умолчание» — шум.
            let who = process.unwrap_or_else(|| "?".to_owned());
            let line = match rule {
                Some(rule) => format!("{who} → {target} · {decision} ({rule})"),
                None => format!("{who} → {target} · {decision}"),
            };
            connection.push_log(LogLevel::Info, line);
        }
        Event::RulesReloaded { .. } => return request(Request::GetConfig),
    }
    Task::none()
}

/// Разбирает главный экран.
pub fn handle_home(app: &mut App, message: HomeMessage) -> Task<Message> {
    match message {
        HomeMessage::ToggleConnection => toggle_connection(app),
        HomeMessage::ServiceReady(ServiceOutcome::Ready) => {
            app.state_mut().connection.starting = false;
            request(Request::Connect { profile: None })
        }
        HomeMessage::ServiceReady(outcome) => {
            app.state_mut().connection.starting = false;
            complain(app, &outcome);
            Task::none()
        }
        HomeMessage::ServiceChecked(outcome) => {
            app.state_mut().connection.starting = false;
            complain(app, &outcome);
            // Спрашиваем в любом случае: подписка достучится, когда служба поднимется.
            crate::app::update::request_initial_state()
        }
    }
}

fn toggle_connection(app: &mut App) -> Task<Message> {
    let connection = &mut app.state_mut().connection;
    if connection.is_busy_with_service() {
        return Task::none();
    }
    // Службы нет — ставим её сами.
    if !connection.online {
        connection.starting = true;
        connection.push_log(LogLevel::Info, crate::i18n::s().service_starting.to_owned());
        return Task::perform(ensure_service(), |ready| {
            Message::Home(HomeMessage::ServiceReady(ready))
        });
    }

    if connection.tunnel.is_active() || connection.tunnel.is_busy() {
        request(Request::Disconnect)
    } else {
        request(Request::Connect { profile: None })
    }
}

/// Пишет в журнал и в файл, почему службы нет; журнал окна живёт до закрытия.
fn complain(app: &mut App, outcome: &ServiceOutcome) {
    let message = match outcome {
        ServiceOutcome::Ready => return,
        ServiceOutcome::Refused => crate::i18n::s().service_needs_rights.to_owned(),
        ServiceOutcome::Failed(reason) => reason.clone(),
    };

    tracing::error!(%message, "служба не поднялась");
    app.state_mut()
        .connection
        .push_log(LogLevel::Error, message);
}

/// Опускает тоннель и останавливает службу перед закрытием окна.
///
/// Прав не просит: служба уже работает с нужными и выходит с нулевым кодом,
/// поэтому launchd и systemd её не перезапускают. Ждёт не дольше `SHUTDOWN_WAIT`.
pub async fn shutdown_service() {
    let _ = tokio::time::timeout(
        SHUTDOWN_WAIT,
        crate::ipc::client::send(penguin_ipc::schema::Request::Shutdown),
    )
    .await;
}

/// Проверяет службу при открытии окна и поднимает, если она молчит.
///
/// Права просит только когда нужно: окно UAC при каждом запуске приучает
/// нажимать «Да», не читая.
pub async fn ensure_at_startup() -> ServiceOutcome {
    // Отвечать может служба от другой сборки.
    let ours = tokio::task::spawn_blocking(penguin_platform::service::matches_current_executable)
        .await
        .unwrap_or(false);

    // Спрашивается ответ, а не соединение: зависший демон соединение принимает.
    if ours && let Some(running) = penguin_ipc::client::greet_service().await {
        if !penguin_platform::build::is_stale(&running, &penguin_platform::build_stamp()) {
            return ServiceOutcome::Ready;
        }
        tracing::info!("служба работает прежней сборкой — перезапускаю");
        return elevated_service(&["service", "restart"]).await;
    }

    elevated_service(&["service", "ensure"]).await
}

async fn ensure_service() -> ServiceOutcome {
    elevated_service(&["service", "ensure"]).await
}

/// Выполняет команду службы с правами и ждёт ответа службы.
///
/// Единственное место, где окно просит права.
async fn elevated_service(arguments: &'static [&'static str]) -> ServiceOutcome {
    let asked = tokio::task::spawn_blocking(move || {
        // Личность и конфиг берутся до смены пользователя в pkexec/osascript.
        let mut arguments: Vec<String> = arguments.iter().map(|arg| (*arg).to_owned()).collect();
        if let Some(uid) = penguin_ipc::current_user_id() {
            arguments.extend(["--controller-uid".to_owned(), uid.to_string()]);
        }
        if let Ok(paths) = penguin_config::Paths::user()
            && paths.config_file().is_file()
            && let Ok(path) = std::path::absolute(paths.config_file())
        {
            arguments.extend(["--import-config".to_owned(), path.display().to_string()]);
        }
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        penguin_platform::run_elevated(&borrowed)
    })
    .await;

    match asked {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return ServiceOutcome::Refused,
        Ok(Err(err)) => return ServiceOutcome::Failed(err.to_string()),
        Err(err) => return ServiceOutcome::Failed(err.to_string()),
    }

    // Канал открывается не мгновенно; ждём ответа, а не соединения.
    let deadline = tokio::time::Instant::now() + SERVICE_WAIT;
    while tokio::time::Instant::now() < deadline {
        if penguin_ipc::client::answers_service().await {
            return ServiceOutcome::Ready;
        }
        tokio::time::sleep(SERVICE_WAIT_STEP).await;
    }
    ServiceOutcome::Failed(crate::i18n::s().service_silent.to_owned())
}

#[cfg(test)]
mod tests {
    use penguin_core::state::TunnelState;
    use penguin_ipc::schema::{LogLevel, StatusReport};

    use super::*;

    fn app() -> App {
        let (app, _task) = App::new(uikit::ThemeType::Dark, false);
        app
    }

    #[test]
    fn config_response_clears_the_dirty_flag() {
        let mut app = app();
        app.state_mut().dirty = true;

        let _ = handle_response(&mut app, Response::Config(Box::default()));
        assert!(!app.state().dirty);
    }

    #[test]
    fn error_goes_to_the_log_not_a_modal() {
        let mut app = app();
        let _ = handle_response(&mut app, Response::error("сеть пропала", false));

        let line = app.state().connection.log.back().expect("строка есть");
        assert_eq!(line.level, LogLevel::Error);
        assert!(line.message.contains("сеть"));
    }

    #[test]
    fn losing_the_daemon_marks_us_offline() {
        let mut app = app();
        let _ = handle(
            &mut app,
            IpcMessage::Disconnected("служба остановлена".to_owned()),
        );

        assert!(!app.state().connection.online);
        assert_eq!(app.state().connection.tunnel, TunnelState::Disconnected);
    }

    #[test]
    fn empty_reason_means_we_connected() {
        let mut app = app();
        app.state_mut().connection.mark_offline("была ошибка");

        let _ = handle(&mut app, IpcMessage::Disconnected(String::new()));
        assert!(app.state().connection.online);
        assert!(app.state().connection.error.is_none());
    }

    #[test]
    fn status_response_updates_the_tunnel() {
        let mut app = app();
        let _ = handle_response(
            &mut app,
            Response::Status(Box::new(StatusReport {
                state: TunnelState::Connected {
                    profile: penguin_core::id::ProfileId::new("home"),
                    uptime_secs: 5,
                },
                traffic: Default::default(),
                rate: Default::default(),
                connections: 3,
                rules: 0,
                mode: "full".to_owned(),
                rtt: None,
            })),
        );

        assert!(app.state().connection.tunnel.is_active());
        assert_eq!(app.state().connection.connections, 3);
    }

    #[test]
    fn a_fresh_window_says_it_is_starting_not_that_nobody_answers() {
        let app = app();
        assert!(app.state().connection.starting);
        assert!(!app.state().connection.online);
    }

    #[test]
    fn checking_the_service_ends_the_waiting() {
        for outcome in [
            ServiceOutcome::Ready,
            ServiceOutcome::Refused,
            ServiceOutcome::Failed("нет polkit".to_owned()),
        ] {
            let mut app = app();
            let _ = handle_home(&mut app, HomeMessage::ServiceChecked(outcome.clone()));
            assert!(!app.state().connection.starting, "исход {outcome:?}");
        }
    }

    #[test]
    fn a_refused_prompt_is_explained() {
        let mut app = app();
        let _ = handle_home(
            &mut app,
            HomeMessage::ServiceChecked(ServiceOutcome::Refused),
        );

        let line = app.state().connection.log.back().expect("строка есть");
        assert_eq!(line.level, LogLevel::Error);
        assert_eq!(line.message, crate::i18n::s().service_needs_rights);
    }

    #[test]
    fn a_real_failure_says_what_happened() {
        let mut app = app();
        let _ = handle_home(
            &mut app,
            HomeMessage::ServiceChecked(ServiceOutcome::Failed("не найден pkexec".to_owned())),
        );

        let line = app.state().connection.log.back().expect("строка есть");
        assert_eq!(line.message, "не найден pkexec");
    }

    #[test]
    fn the_service_is_not_polled_while_we_are_busy_with_it() {
        let mut connection = crate::app::state::Connection::default();
        connection.starting = true;
        assert!(connection.is_busy_with_service());

        connection.starting = false;
        connection.stopping = true;
        assert!(connection.is_busy_with_service());

        connection.stopping = false;
        assert!(!connection.is_busy_with_service());
    }

    #[test]
    fn repeated_connect_does_not_start_another_elevation() {
        let mut app = app();
        let before = app.state().connection.log.len();
        let _ = handle_home(&mut app, HomeMessage::ToggleConnection);
        assert!(app.state().connection.starting);
        assert_eq!(app.state().connection.log.len(), before);
        app.state_mut().connection.starting = false;
        app.state_mut().connection.stopping = true;
        let _ = handle_home(&mut app, HomeMessage::ToggleConnection);
        assert!(!app.state().connection.starting);
        assert_eq!(app.state().connection.log.len(), before);
    }

    #[test]
    fn a_working_service_is_not_complained_about() {
        let mut app = app();
        let _ = handle_home(&mut app, HomeMessage::ServiceChecked(ServiceOutcome::Ready));
        assert!(app.state().connection.log.is_empty());
    }

    #[test]
    fn connecting_clears_the_starting_flag() {
        let mut app = app();
        let _ = handle(&mut app, IpcMessage::Disconnected(String::new()));
        assert!(!app.state().connection.starting);
    }

    #[test]
    fn probe_results_stop_the_spinner() {
        let mut app = app();
        app.state_mut().servers.probing = true;

        let _ = handle_response(
            &mut app,
            Response::Probes {
                results: Vec::new(),
            },
        );
        assert!(!app.state().servers.probing);
    }
}
