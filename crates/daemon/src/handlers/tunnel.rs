//! Подключение, отключение, состояние.

use std::sync::Arc;

use penguin_core::id::ProfileId;
use penguin_engine::Engine;
use penguin_ipc::schema::{Response, StatusReport};
use tokio_util::sync::CancellationToken;

/// Собирает полное состояние клиента.
pub fn status(engine: &Arc<Engine>) -> Response {
    let metrics = engine.metrics();
    let traffic = metrics.total();

    Response::Status(Box::new(StatusReport {
        state: engine.state(),
        traffic,
        // Скорость приходит событиями
        rate: penguin_core::stats::Throughput::default(),
        connections: metrics.live_connections(),
        rules: engine.router().rule_count(),
        mode: engine.router().mode().as_str().to_owned(),
        rtt: None,
    }))
}

/// Поднимает тоннель.
pub async fn connect(engine: &Arc<Engine>, profile: Option<ProfileId>) -> Response {
    match engine.connect(profile).await {
        Ok(()) => Response::Ok,
        Err(err) => {
            let needs_user_action = err.needs_user_action();
            Response::error(err, needs_user_action)
        }
    }
}

/// Опускает тоннель.
pub async fn disconnect(engine: &Arc<Engine>) -> Response {
    match engine.disconnect().await {
        Ok(()) => Response::Ok,
        // Неудачный откат оставляет маршруты и правила: пользователь должен узнать
        Err(err) => Response::error(err, true),
    }
}

/// Опускает тоннель и останавливает службу.
///
/// Сначала тоннель, потом отмена: ответ окну уходит после снятия TUN и маршрутов.
pub async fn shutdown(engine: &Arc<Engine>, cancel: &CancellationToken) -> Response {
    let response = disconnect(engine).await;
    // Иначе launchd сразу поднимет службу снова; запрос — забота службы, а не отладочного запуска.
    if penguin_platform::is_elevated()
        && let Err(err) = penguin_platform::service::user_start::withdraw()
    {
        tracing::warn!(%err, "запрос запуска службы не снят");
    }
    cancel.cancel();
    response
}

#[cfg(test)]
mod tests {
    use penguin_config::RootConfig;

    use super::*;

    fn engine() -> Arc<Engine> {
        Engine::new(RootConfig::default()).expect("движок собирается")
    }

    #[test]
    fn status_reports_the_mode() {
        let Response::Status(status) = status(&engine()) else {
            panic!("не тот ответ")
        };
        assert_eq!(status.mode, "tunnel");
        assert_eq!(status.rules, 0);
    }

    #[tokio::test]
    async fn disconnect_without_connect_succeeds() {
        assert!(!disconnect(&engine()).await.is_error());
    }

    #[tokio::test]
    async fn shutdown_lowers_the_tunnel_before_it_stops_the_service() {
        // Отмена раньше отката оставила бы живой TUN
        let cancel = CancellationToken::new();
        assert!(!shutdown(&engine(), &cancel).await.is_error());
        assert!(cancel.is_cancelled());
    }
}
