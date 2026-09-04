//! Подключение, отключение, смена профиля.

use iced::Task;
use penguin_ipc::schema::{Event, Request, Response};

use crate::app::App;
use crate::app::message::{HomeMessage, IpcMessage, Message, ServiceOutcome};
use crate::app::update::request;

/// Разбирает всё, что пришло от демона.
pub fn handle(app: &mut App, message: IpcMessage) -> Task<Message> {
    match message {
        IpcMessage::Response(response) => handle_response(app, *response),
        IpcMessage::Event(event) => handle_event(app, *event),
        IpcMessage::Disconnected(reason) => {
            // Пустая причина означает удачное подключение подписки — она
            // сообщает о нём тем же сообщением, чтобы не заводить второе.
            if reason.is_empty() {
                app.state_mut().connection.online = true;
                app.state_mut().connection.starting = false;
                app.state_mut().connection.error = None;
                return crate::app::update::request_initial_state();
            }
            app.state_mut().connection.mark_offline(reason);
            Task::none()
        }
    }
}

/// Разбирает ответ на запрос.
fn handle_response(app: &mut App, response: Response) -> Task<Message> {
    let state = app.state_mut();

    match response {
        Response::Ok | Response::Pong { .. } => Task::none(),

        Response::Status(status) => {
            state.connection.apply_status(&status);
            Task::none()
        }

        Response::Config(config) => {
            state.config = *config;
            // Обе копии — то, что лежит у демона: правок в окне больше нет.
            state.saved = state.config.clone();
            state.dirty = false;
            Task::none()
        }

        Response::Explanation(explanation) => {
            state.split_tunnel.probe_result = Some(*explanation);
            Task::none()
        }

        Response::Processes { apps } => {
            state.split_tunnel.running_apps = apps;
            Task::none()
        }

        Response::Probes { results } => {
            state.servers.probing = false;
            state.servers.latencies = results
                .into_iter()
                .map(|row| (row.profile, row.rtt_millis))
                .collect();
            Task::none()
        }

        Response::Error { message, .. } => {
            // Ошибка попадает в журнал окна, а не в модальное окно: половина
            // ошибок приходит фоном — от переподключения, от проверки
            // задержки, — и останавливать ими работу незачем.
            state
                .connection
                .push_log(penguin_ipc::schema::LogLevel::Error, message);
            Task::none()
        }
    }
}

/// Разбирает событие.
fn handle_event(app: &mut App, event: Event) -> Task<Message> {
    let state = app.state_mut();

    match event {
        Event::State { state: tunnel } => {
            state.connection.set_tunnel(tunnel);
            state.connection.online = true;
            Task::none()
        }

        Event::Throughput {
            rate,
            total,
            connections,
        } => {
            state.connection.apply_throughput(rate, total, connections);
            Task::none()
        }

        Event::Log { level, message } => {
            state.connection.push_log(level, message);
            Task::none()
        }

        Event::Decision {
            target,
            process,
            decision,
            rule,
        } => {
            // Приложение, куда и каким путём — три вопроса, ради которых
            // журнал и открывают. Правило дописывается, только когда оно
            // сработало: «умолчание режима» в каждой строке — это шум.
            let who = process.unwrap_or_else(|| "?".to_owned());
            let line = match rule {
                Some(rule) => format!("{who} → {target} · {decision} ({rule})"),
                None => format!("{who} → {target} · {decision}"),
            };
            state
                .connection
                .push_log(penguin_ipc::schema::LogLevel::Info, line);
            Task::none()
        }

        // Правила пересобраны демоном — перечитываем настройки, чтобы окно
        // показывало то же, что у него.
        Event::RulesReloaded { .. } => request(Request::GetConfig),
    }
}

/// Разбирает главный экран.
pub fn handle_home(app: &mut App, message: HomeMessage) -> Task<Message> {
    match message {
        HomeMessage::ToggleConnection => {
            // Службы нет — значит, её надо поставить, а не сообщать об этом
            // человеку и ждать, пока он сам догадается. Он нажал «Подключить»:
            // остальное — наша забота.
            if !app.state().connection.online {
                app.state_mut().connection.starting = true;
                app.state_mut().connection.push_log(
                    penguin_ipc::schema::LogLevel::Info,
                    crate::i18n::s().service_starting.to_owned(),
                );
                return Task::perform(ensure_service(), |ready| {
                    Message::Home(HomeMessage::ServiceReady(ready))
                });
            }

            // Одна кнопка на оба действия: пользователь думает не «подключить
            // или отключить», а «включить или выключить».
            if app.state().connection.tunnel.is_active() || app.state().connection.tunnel.is_busy()
            {
                request(Request::Disconnect)
            } else {
                request(Request::Connect { profile: None })
            }
        }

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
            // Спрашиваем в любом случае. Не вышло сейчас — подписка
            // достучится сама, когда служба поднимется, и ответ придёт тогда.
            crate::app::update::request_initial_state()
        }
    }
}

/// Пишет в журнал окна, почему службы нет.
///
/// Отказ в системном окне и сбой — разные строки: первое человек сделал сам и
/// знает почему, второе он видит впервые и лечится оно совсем иначе.
fn complain(app: &mut App, outcome: &ServiceOutcome) {
    let message = match outcome {
        ServiceOutcome::Ready => return,
        ServiceOutcome::Refused => crate::i18n::s().service_needs_rights.to_owned(),
        ServiceOutcome::Failed(reason) => reason.clone(),
    };
    app.state_mut()
        .connection
        .push_log(penguin_ipc::schema::LogLevel::Error, message);
}

/// Опускает тоннель и останавливает службу — перед тем, как закрыть окно.
///
/// Прав не спрашивает: службу останавливает не диспетчер, а она сама, по
/// запросу из канала управления. Она уже работает с нужными правами, а окну
/// UAC при каждом закрытии приучил бы нажимать «Да», не читая.
///
/// Ответа ждёт, но не вечно: закрытие не должно зависеть от того, ответила ли
/// служба. Не ответила за отведённое время — окно всё равно закрывается, а
/// служба доводит остановку сама.
pub async fn shutdown_service() {
    let _ = tokio::time::timeout(
        SHUTDOWN_WAIT,
        crate::ipc::client::send(penguin_ipc::schema::Request::Shutdown),
    )
    .await;
}

/// Сколько ждать, пока служба опустит тоннель и остановится.
///
/// Снять TUN-адаптер, вернуть маршруты и DNS — это секунды, и закрыть окно
/// раньше значило бы соврать: программы на экране нет, а сеть ещё наша.
const SHUTDOWN_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Проверяет службу при открытии окна и поднимает её, если она молчит.
///
/// Сначала вопрос, а не действие: служба стоит с автозапуском и почти всегда
/// уже работает. Просить права в этом случае незачем — окно UAC при каждом
/// запуске приучает нажимать «Да», не читая.
pub async fn ensure_at_startup() -> ServiceOutcome {
    // Мало того, что служба отвечает: ответить может и служба от другой
    // сборки — от прошлой версии, из другого каталога. Тоннель тогда поднимает
    // не та программа, которую запустили, и рядом с ней может не оказаться ни
    // драйвера, ни настроек.
    let ours = tokio::task::spawn_blocking(penguin_platform::service::matches_current_executable)
        .await
        .unwrap_or(false);

    if ours && let Ok(mut client) = penguin_ipc::Client::connect().await {
        // Тот файл и служба отвечает — остаётся спросить, тем ли образом она
        // запущена. Отвечать может и служба, поднятая до того, как файл
        // заменили: тоннель она держит прежним кодом.
        let running = client
            .hello()
            .await
            .map(|(_, build)| build)
            .unwrap_or_default();

        if !penguin_platform::build::is_stale(&running, &penguin_platform::build_stamp()) {
            return ServiceOutcome::Ready;
        }
        tracing::info!("служба работает прежней сборкой — перезапускаю");
        return elevated_service(&["service", "restart"]).await;
    }

    elevated_service(&["service", "ensure"]).await
}

/// Доводит службу до рабочего состояния и дожидается, пока она ответит.
///
/// Установка идёт в отдельном процессе с правами администратора — иначе никак:
/// права в Windows получает только новый процесс. Всё это время окно обязано
/// оставаться живым, поэтому ожидание уехало в задачу.
async fn ensure_service() -> ServiceOutcome {
    elevated_service(&["service", "ensure"]).await
}

/// Выполняет команду службы с правами и дожидается, пока служба ответит.
async fn elevated_service(arguments: &'static [&'static str]) -> ServiceOutcome {
    let asked =
        tokio::task::spawn_blocking(move || penguin_platform::run_elevated(arguments)).await;

    match asked {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return ServiceOutcome::Refused,
        // Настоящий сбой: нет службы запроса прав, программу не пустили,
        // установка не удалась. Человек должен прочитать причину, а не
        // «нужны права» — оно тут ни при чём.
        Ok(Err(err)) => return ServiceOutcome::Failed(err.to_string()),
        Err(err) => return ServiceOutcome::Failed(err.to_string()),
    }

    // Служба запущена, но канал управления открывается не мгновенно. Без
    // ожидания первое же подключение упёрлось бы в отказ, и человек увидел бы
    // ошибку там, где всё получилось.
    for _ in 0..SERVICE_WAIT_ATTEMPTS {
        if penguin_ipc::Client::connect().await.is_ok() {
            return ServiceOutcome::Ready;
        }
        tokio::time::sleep(SERVICE_WAIT_STEP).await;
    }
    ServiceOutcome::Failed(crate::i18n::s().service_silent.to_owned())
}

/// Сколько раз спросить службу, прежде чем сдаться.
const SERVICE_WAIT_ATTEMPTS: usize = 20;

/// Пауза между попытками.
const SERVICE_WAIT_STEP: std::time::Duration = std::time::Duration::from_millis(250);

#[cfg(test)]
mod tests {
    use penguin_core::state::TunnelState;
    use penguin_ipc::schema::{LogLevel, StatusReport};

    use super::*;

    fn app() -> App {
        // Приложение создаётся без окна: `update` от него не зависит.
        let (app, _task) = App::new(uikit::ThemeType::Dark);
        app
    }

    #[test]
    fn config_response_clears_the_dirty_flag() {
        // Пришло то, что лежит у демона: несохранённых правок больше нет.
        let mut app = app();
        app.state_mut().dirty = true;

        let _ = handle_response(&mut app, Response::Config(Box::default()));
        assert!(!app.state().dirty);
    }

    #[test]
    fn error_goes_to_the_log_not_a_modal() {
        // Половина ошибок приходит фоном; останавливать ими работу незачем.
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
        // Подписка сообщает об удачном подключении тем же сообщением, чтобы
        // не заводить второе.
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
        // Первый кадр рисуется раньше ответа службы. «Служба не отвечает» в
        // нём — обвинение до того, как её спросили.
        let app = app();
        assert!(app.state().connection.starting);
        assert!(!app.state().connection.online);
    }

    #[test]
    fn checking_the_service_ends_the_waiting() {
        // Флаг снимается во всех исходах: иначе окно навсегда осталось бы с
        // надписью «Запускаю службу».
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
        // Отказ в системном окне — решение человека, но молчать в ответ
        // нельзя: окно осталось бы пустым без единого объяснения.
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
        // «Нужны права» на машине без службы запроса прав — тупик: человек
        // нажимает «Подключить» снова и снова и видит то же самое.
        let mut app = app();
        let _ = handle_home(
            &mut app,
            HomeMessage::ServiceChecked(ServiceOutcome::Failed("не найден pkexec".to_owned())),
        );

        let line = app.state().connection.log.back().expect("строка есть");
        assert_eq!(line.message, "не найден pkexec");
    }

    #[test]
    fn a_working_service_is_not_complained_about() {
        let mut app = app();
        let _ = handle_home(&mut app, HomeMessage::ServiceChecked(ServiceOutcome::Ready));
        assert!(app.state().connection.log.is_empty());
    }

    #[test]
    fn connecting_clears_the_starting_flag() {
        // Связь появилась — ждать больше нечего.
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
