//! Запросы к демону.
//!
//! Каждый запрос — отдельное соединение. Держать одно постоянное было бы
//! экономнее, но потребовало бы состояния и очереди: `iced` вызывает
//! `update` из одного места, а ответы приходят когда придут. Открыть
//! именованный канал стоит микросекунды, и на фоне обмена с демоном это ничто.
//!
//! Поток событий — отдельная история, он живёт в подписке
//! ([`super::subscription`]) и соединение держит постоянно.

use penguin_ipc::schema::{Request, Response};
use penguin_ipc::{Client, IpcResult};

/// Отправляет запрос и возвращает ответ.
pub async fn send(request: Request) -> IpcResult<Response> {
    let mut client = Client::connect().await?;
    client.request(request).await
}

/// Отправляет запрос, превращая ошибку связи в ответ об ошибке.
///
/// Так удобнее интерфейсу: у него один путь обработки — ответ, — и незачем
/// разводить «демон ответил отказом» и «демон не ответил» по разным веткам.
/// Пользователю важно одно и то же: не получилось, и вот почему.
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

    #[tokio::test]
    async fn missing_daemon_becomes_an_error_response() {
        // У интерфейса один путь обработки — ответ; разводить «отказал» и
        // «не ответил» по разным веткам незачем.
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
