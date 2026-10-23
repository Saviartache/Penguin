//! Обработчики запросов канала управления.
//!
//! Тонкий слой без собственной логики: запрос, вызов движка, ответ. Типы канала
//! отделены от типов движка, т.к. демон и интерфейс обновляются раздельно.

pub mod diagnostics;
pub mod geoip;
pub mod processes;
pub mod profiles;
pub mod rules;
pub mod tunnel;

use std::sync::Arc;

use async_trait::async_trait;
use penguin_config::ConfigStore;
use penguin_engine::Engine;
use penguin_ipc::schema::{Event, Request, Response};
use penguin_ipc::server::Handler;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Версия демона.
///
/// Уходит в ответе на `Ping`; интерфейс сверяет со своей.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Обработчик запросов демона.
pub struct DaemonHandler {
    engine: Arc<Engine>,
    /// Куда писать настройки; про файлы движок не знает.
    store: Arc<ConfigStore>,
    /// События, переведённые в формат провода.
    events: broadcast::Sender<Event>,
    /// Остановка демона; общая с командой «стоп» диспетчера и [`Request::Shutdown`].
    cancel: CancellationToken,
    /// Отпечаток запущенного файла, снятый при создании: на диске он мог смениться.
    build: String,
}

impl std::fmt::Debug for DaemonHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonHandler")
            .field("state", &self.engine.state())
            .finish()
    }
}

impl DaemonHandler {
    /// Создаёт обработчик и запускает перевод событий.
    pub fn new(
        engine: Arc<Engine>,
        store: Arc<ConfigStore>,
        cancel: CancellationToken,
    ) -> Arc<Self> {
        let (events, _) = broadcast::channel(penguin_engine::events::CHANNEL_CAPACITY);
        spawn_event_bridge(&engine, events.clone());
        Arc::new(Self {
            engine,
            store,
            events,
            cancel,
            build: penguin_platform::build_stamp(),
        })
    }
}

#[async_trait]
impl Handler for DaemonHandler {
    async fn handle(&self, request: Request) -> Response {
        match request {
            Request::Ping => Response::Pong {
                version: VERSION.to_owned(),
                build: self.build.clone(),
            },

            Request::Status => tunnel::status(&self.engine),
            Request::Connect { profile } => tunnel::connect(&self.engine, profile).await,
            Request::Disconnect => tunnel::disconnect(&self.engine).await,
            Request::Shutdown => tunnel::shutdown(&self.engine, &self.cancel).await,

            Request::GetConfig => profiles::get_config(&self.engine),
            Request::SetConfig { config } => {
                profiles::set_config(&self.engine, &self.store, *config)
            }
            Request::Probe { profile } => profiles::probe_profiles(&self.engine, profile).await,

            Request::Explain {
                destination,
                process,
                udp,
            } => rules::explain(&self.engine, &destination, process.as_deref(), udp),

            Request::ListProcesses => processes::list(),

            Request::PutGeoIp {
                offset,
                total,
                data,
            } => geoip::put(
                &self.engine,
                &self.store.paths().geoip_file(),
                offset,
                total,
                &data,
            ),

            // Обрабатывается сервером
            Request::Subscribe => Response::Ok,
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }
}

/// Переводит события движка в формат провода.
///
/// Отдельная задача: подписчиков может не быть, движок о них не знает.
fn spawn_event_bridge(engine: &Arc<Engine>, outgoing: broadcast::Sender<Event>) {
    let mut incoming = engine.events().subscribe();

    tokio::spawn(async move {
        loop {
            match incoming.recv().await {
                Ok(event) => {
                    if let Some(translated) = translate(event) {
                        let _ = outgoing.send(translated);
                    }
                }
                // Пропуск событий допустим
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

/// Переводит одно событие.
fn translate(event: penguin_engine::Event) -> Option<Event> {
    use penguin_engine::events::Event as Inner;
    use penguin_engine::events::LogLevel as InnerLevel;
    use penguin_ipc::schema::LogLevel;

    Some(match event {
        Inner::State { state } => Event::State { state },
        Inner::Throughput {
            rate,
            total,
            connections,
        } => Event::Throughput {
            rate,
            total,
            connections,
        },
        Inner::Log { level, message } => Event::Log {
            level: match level {
                InnerLevel::Info => LogLevel::Info,
                InnerLevel::Warning => LogLevel::Warning,
                InnerLevel::Error => LogLevel::Error,
            },
            message,
        },
        Inner::Decision {
            target,
            process,
            process_path,
            decision,
            rule,
        } => Event::Decision {
            target,
            process,
            process_path,
            decision,
            rule,
        },
        Inner::RulesReloaded { count } => Event::RulesReloaded { count },
        // Видна по смене состояния
        Inner::ProfileChanged { .. } => return None,
    })
}

#[cfg(test)]
mod tests {
    use penguin_config::RootConfig;
    use penguin_core::state::TunnelState;

    use super::*;

    fn handler() -> Arc<DaemonHandler> {
        let engine = Engine::new(RootConfig::default()).expect("движок собирается");
        // `SetConfig` пишет на диск: нужен временный каталог
        let dir = std::env::temp_dir().join(format!("penguin-ipc-{}", std::process::id()));
        let store = ConfigStore::new(penguin_config::Paths::rooted(dir));

        DaemonHandler::new(engine, Arc::new(store), CancellationToken::new())
    }

    #[tokio::test]
    async fn ping_reports_the_version() {
        let Response::Pong { version, .. } = handler().handle(Request::Ping).await else {
            panic!("не тот ответ");
        };
        assert_eq!(version, VERSION);
        assert!(!version.is_empty());
    }

    #[tokio::test]
    async fn status_works_without_a_tunnel() {
        let Response::Status(status) = handler().handle(Request::Status).await else {
            panic!("не тот ответ");
        };
        assert_eq!(status.state, TunnelState::Disconnected);
    }

    #[tokio::test]
    async fn connect_without_profiles_says_what_is_wrong() {
        let response = handler().handle(Request::Connect { profile: None }).await;
        let Response::Error {
            message,
            needs_user_action,
        } = response
        else {
            panic!("подключение без профилей не должно удаваться");
        };
        assert!(needs_user_action, "пользователю надо добавить профиль");
        assert!(message.contains("профил"), "невнятное сообщение: {message}");
    }

    #[tokio::test]
    async fn config_round_trips_through_the_channel() {
        let handler = handler();
        let Response::Config(config) = handler.handle(Request::GetConfig).await else {
            panic!("не тот ответ");
        };
        assert_eq!(config.version, penguin_config::SCHEMA_VERSION);

        let response = handler.handle(Request::SetConfig { config }).await;
        assert!(!response.is_error(), "настройки не приняты: {response:?}");
    }

    #[tokio::test]
    async fn shutdown_stops_the_daemon() {
        let cancel = CancellationToken::new();
        let engine = Engine::new(RootConfig::default()).expect("движок собирается");
        let dir = std::env::temp_dir().join(format!("penguin-ipc-stop-{}", std::process::id()));
        let store = ConfigStore::new(penguin_config::Paths::rooted(dir));
        let handler = DaemonHandler::new(engine, Arc::new(store), cancel.clone());

        assert!(!handler.handle(Request::Shutdown).await.is_error());
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn profile_change_has_no_wire_event() {
        let event = penguin_engine::Event::ProfileChanged {
            outbound: penguin_core::id::OutboundId::new("home"),
        };
        assert!(translate(event).is_none());
    }

    #[test]
    fn log_levels_survive_translation() {
        use penguin_engine::events::LogLevel as InnerLevel;
        use penguin_ipc::schema::LogLevel;

        let event = penguin_engine::Event::Log {
            level: InnerLevel::Warning,
            message: "сеть пропала".to_owned(),
        };
        let Some(Event::Log { level, message }) = translate(event) else {
            panic!("не то событие");
        };
        assert_eq!(level, LogLevel::Warning);
        assert_eq!(message, "сеть пропала");
    }
}
