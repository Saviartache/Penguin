//! Подписка iced на поток событий демона.
//!
//! Интерфейс не опрашивает демона, а слушает. Разница видна на графике
//! скорости: опрос раз в секунду даёт рваную линию и лишний обмен по каналу,
//! подписка — ровный поток.
//!
//! Подписка сама переподключается. Демон может быть не запущен в момент
//! старта окна, может быть перезапущен при обновлении, может упасть — во всех
//! случаях окно обязано подхватить связь само, а не требовать перезапуска.

use std::time::Duration;

use iced::Subscription;
use iced::futures::stream;
use penguin_ipc::Client;

use crate::app::message::{IpcMessage, Message};

/// Пауза перед повторной попыткой связаться с демоном.
///
/// Секунда: чаще — бессмысленный поток попыток в журнале, реже — заметная
/// задержка после запуска службы.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Подписка на события демона.
pub fn events() -> Subscription<Message> {
    // `Subscription::run` берёт идентификатор подписки из типа потока и самого
    // указателя на функцию: iced по ним понимает, что это та же подписка, и не
    // создаёт вторую при каждой перерисовке. Замыкание ничего не захватывает,
    // поэтому годится как `fn`-указатель, которого требует `run`.
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

/// В каком состоянии подписка.
enum Stage {
    /// Связи нет, надо подключиться.
    Disconnected,
    /// Слушаем события.
    Listening(penguin_ipc::client::EventStream),
}

/// Подключается к демону и переходит к прослушиванию.
async fn connect() -> (Message, Stage) {
    match Client::connect().await {
        Ok(client) => match client.subscribe().await {
            Ok(stream) => (
                Message::Ipc(IpcMessage::Disconnected(String::new())),
                Stage::Listening(stream),
            ),
            Err(err) => fail(err.to_string()).await,
        },
        Err(err) => fail(err.to_string()).await,
    }
}

/// Сообщает о неудаче и выжидает перед следующей попыткой.
///
/// Пауза именно здесь, а не в вызывающем: без неё поток попыток крутился бы
/// без передышки, пока демон не запущен.
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
        // Чаще — бессмысленный поток попыток, реже — заметная задержка после
        // запуска службы.
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
