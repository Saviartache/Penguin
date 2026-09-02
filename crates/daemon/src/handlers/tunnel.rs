//! Подключение, отключение, состояние.

use std::sync::Arc;

use penguin_core::id::ProfileId;
use penguin_engine::Engine;
use penguin_ipc::schema::{Response, StatusReport};

/// Собирает полное состояние клиента.
pub fn status(engine: &Arc<Engine>) -> Response {
    let metrics = engine.metrics();
    let traffic = metrics.total();

    Response::Status(Box::new(StatusReport {
        state: engine.state(),
        traffic,
        // Мгновенная скорость приходит событиями: считать её здесь означало бы
        // делить на время, прошедшее с непонятно какого момента.
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
        // Неудачный откат — самое серьёзное, что может случиться: в системе
        // остались маршруты или правила брандмауэра, и сеть у пользователя
        // может не работать. Такое обязано дойти до него как требующее
        // внимания.
        Err(err) => Response::error(err, true),
    }
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
        assert_eq!(status.mode, "full");
        assert_eq!(status.rules, 0);
    }

    #[tokio::test]
    async fn disconnect_without_connect_succeeds() {
        assert!(!disconnect(&engine()).await.is_error());
    }
}
