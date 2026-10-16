//! Запросы к демону: каждый — отдельное соединение (дёшево, состояния и очереди
//! не нужно). Поток событий живёт в подписке ([`super::subscription`]).

use penguin_ipc::schema::{Request, Response};
use penguin_ipc::{Client, IpcResult};

/// Сколько ждать запрос, который делает работу.
const WORK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Отправляет запрос и возвращает ответ.
///
/// Со сроком: зависший демон соединение принимает и молчит.
pub async fn send(request: Request) -> IpcResult<Response> {
    let limit = limit_for(&request);

    tokio::time::timeout(limit, async {
        let mut client = Client::connect_service().await?;
        client.request(request).await
    })
    .await
    .unwrap_or(Err(penguin_ipc::IpcError::NoAnswer))
}

/// Срок ответа: работа (подъём, замер задержки, обход процессов) — долго, вопрос
/// из памяти демона — коротко. Признак — `does_work`, не `is_mutating`: замер
/// ничего не меняет, но ходит до каждого сервера.
fn limit_for(request: &Request) -> std::time::Duration {
    if request.does_work() {
        WORK_TIMEOUT
    } else {
        penguin_ipc::client::ANSWER_TIMEOUT
    }
}

/// Отправляет запрос, превращая ошибку связи в ответ об ошибке: у интерфейса один
/// путь обработки.
pub async fn send_or_error(request: Request) -> Response {
    match send(request).await {
        Ok(response) => response,
        Err(err) => {
            let needs_user_action = err.needs_user_action();
            Response::error(err, needs_user_action)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_gets_more_time_than_a_question() {
        assert!(limit_for(&Request::Connect { profile: None }) > limit_for(&Request::Status));
        assert_eq!(
            limit_for(&Request::Ping),
            penguin_ipc::client::ANSWER_TIMEOUT
        );
    }

    #[test]
    fn measuring_latency_is_work_too() {
        assert_eq!(
            limit_for(&Request::Probe { profile: None }),
            limit_for(&Request::Connect { profile: None })
        );
        assert_eq!(
            limit_for(&Request::ListProcesses),
            limit_for(&Request::Connect { profile: None })
        );
    }

    #[tokio::test]
    async fn missing_daemon_becomes_an_error_response() {
        let response = send_or_error(Request::Ping).await;

        match response {
            // Демон работает — законный исход.
            Response::Pong { .. } => {}
            Response::Error {
                message,
                needs_user_action,
            } => {
                assert!(needs_user_action, "запуск службы — дело пользователя");
                assert!(!message.is_empty());
            }
            other => panic!("неожиданный ответ: {other:?}"),
        }
    }
}
