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
///
/// Со сроком: демон, зависший с поднятым тоннелем, соединение принимает — его
/// дослушивает ядро — и молчит. Без срока запрос к такому демону не
/// возвращается никогда, и окно ждёт ответа, которого не будет.
pub async fn send(request: Request) -> IpcResult<Response> {
    let limit = limit_for(&request);

    tokio::time::timeout(limit, async {
        let mut client = Client::connect().await?;
        client.request(request).await
    })
    .await
    .unwrap_or(Err(penguin_ipc::IpcError::DaemonNotRunning))
}

/// Сколько ждать ответа на этот запрос.
///
/// Два срока, потому что запросы разные. Подъём тоннеля — это набор сервера,
/// рукопожатие, маршруты и брандмауэр, и минута тут не расточительность.
/// Вопрос о состоянии или настройках демон отвечает из памяти, и три секунды
/// молчания на него означают, что отвечать некому.
fn limit_for(request: &Request) -> std::time::Duration {
    if request.is_mutating() {
        WORK_TIMEOUT
    } else {
        penguin_ipc::client::ANSWER_TIMEOUT
    }
}

/// Сколько ждать запрос, который делает работу.
const WORK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

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

    #[test]
    fn work_gets_more_time_than_a_question() {
        // Один срок на оба означал бы либо оборванное подключение, либо
        // минуту неподвижного окна в ответ на вопрос к зависшей службе.
        assert!(limit_for(&Request::Connect { profile: None }) > limit_for(&Request::Status));
        assert_eq!(
            limit_for(&Request::Ping),
            penguin_ipc::client::ANSWER_TIMEOUT
        );
    }

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
