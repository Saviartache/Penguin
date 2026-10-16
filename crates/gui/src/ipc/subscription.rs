//! Подписка iced на поток событий демона: слушает, а не опрашивает, и сама
//! переподключается (демон может быть не запущен, перезапущен, упасть).

use std::time::Duration;

use iced::Subscription;
use iced::futures::stream;
use penguin_ipc::Client;

use crate::app::message::{IpcMessage, Message};

/// Пауза перед повторной попыткой: чаще — шум в журнале, реже — задержка после запуска.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Подписка на события демона.
pub fn events() -> Subscription<Message> {
    // Идентификатор берётся из указателя на функцию; замыкание без захвата.
    Subscription::run(|| {
        stream::unfold(Stage::Disconnected, |stage| async move {
            match stage {
                Stage::Disconnected => Some(connect().await),
                Stage::Listening(mut stream) => match stream.next().await {
                    Ok(event) => Some((
                        Message::Ipc(IpcMessage::Event(Box::new(event))),
                        Stage::Listening(stream),
                    )),
                    Err(err) => Some((
                        Message::Ipc(IpcMessage::Disconnected(err.to_string())),
                        Stage::Disconnected,
                    )),
                },
            }
        })
    })
}

enum Stage {
    /// Связи нет, надо подключиться.
    Disconnected,
    /// Слушаем события.
    Listening(penguin_ipc::client::EventStream),
}

async fn connect() -> (Message, Stage) {
    let result = tokio::time::timeout(penguin_ipc::client::ANSWER_TIMEOUT, async {
        Client::connect_service().await?.subscribe().await
    })
    .await
    .unwrap_or(Err(penguin_ipc::IpcError::NoAnswer));
    match result {
        Ok(stream) => (
            Message::Ipc(IpcMessage::Disconnected(String::new())),
            Stage::Listening(stream),
        ),
        Err(err) => fail(err.to_string()).await,
    }
}

/// Сообщает о неудаче и выжидает: без паузы попытки крутились бы без передышки.
async fn fail(reason: String) -> (Message, Stage) {
    tokio::time::sleep(RECONNECT_DELAY).await;
    (
        Message::Ipc(IpcMessage::Disconnected(reason)),
        Stage::Disconnected,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_delay_is_reasonable() {
        assert!(RECONNECT_DELAY >= Duration::from_millis(500));
        assert!(RECONNECT_DELAY <= Duration::from_secs(5));
    }

    #[tokio::test]
    async fn failing_to_connect_waits_before_retrying() {
        let started = std::time::Instant::now();
        let (message, stage) = fail("демон не запущен".to_owned()).await;

        assert!(matches!(message, Message::Ipc(IpcMessage::Disconnected(_))));
        assert!(matches!(stage, Stage::Disconnected));
        assert!(started.elapsed() >= RECONNECT_DELAY, "пауза не выдержана");
    }
}
