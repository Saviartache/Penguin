//! Транспорт канала управления.
//!
//! На Windows это именованный канал, на остальных системах — сокет в
//! файловой системе. Общего у них ровно столько, сколько нужно: имя, по
//! которому обе стороны находят друг друга, и поток байт.

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::{GenericNamespaced, ListenerOptions, ToNsName};

use crate::error::{IpcError, IpcResult};

/// Имя канала управления.
///
/// Одно на всю систему: демон один, и клиентов у него сколько угодно.
pub const CHANNEL_NAME: &str = "penguin-control.sock";

/// Открывает канал на приём.
///
/// На Windows к нему сразу применяется дескриптор безопасности: канал с
/// умолчанием доступен шире, чем нужно, а через него можно выключить kill
/// switch.
pub fn listen() -> IpcResult<LocalSocketListener> {
    let name = CHANNEL_NAME
        .to_ns_name::<GenericNamespaced>()
        .map_err(|e| IpcError::Transport(format!("имя канала: {e}")))?;

    let options = ListenerOptions::new().name(name);

    #[cfg(windows)]
    let options = windows::secure(options)?;

    options.create_tokio().map_err(|e| match e.kind() {
        // Windows отвечает «отказано в доступе», а не «занято», когда канал с
        // таким именем уже создан другим процессом с иным дескриптором
        // безопасности. Создать именованный канал в своём пространстве имён
        // обычный пользователь может всегда, так что другой причины для
        // отказа тут практически не бывает — и сообщать про доступ значило бы
        // сбивать с толку.
        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied => {
            IpcError::AlreadyRunning
        }
        _ => IpcError::Transport(format!("не удалось открыть канал управления: {e}")),
    })
}

/// Подключается к каналу.
pub async fn connect() -> IpcResult<LocalSocketStream> {
    let name = CHANNEL_NAME
        .to_ns_name::<GenericNamespaced>()
        .map_err(|e| IpcError::Transport(format!("имя канала: {e}")))?;

    LocalSocketStream::connect(name).await.map_err(|e| {
        // Канала нет — демон не запущен. Самая частая причина, и сообщение
        // должно говорить именно это, а не «файл не найден».
        match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                IpcError::DaemonNotRunning
            }
            std::io::ErrorKind::PermissionDenied => IpcError::AccessDenied,
            _ => IpcError::Transport(format!("не удалось подключиться к демону: {e}")),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_name_is_stable() {
        // Имя знают обе стороны; менять его — значит развести уже
        // установленные демон и интерфейс.
        assert_eq!(CHANNEL_NAME, "penguin-control.sock");
    }

    #[tokio::test]
    async fn connecting_without_a_daemon_says_so() {
        // Самая частая ошибка у пользователя: служба не запущена. Сообщение
        // должно говорить именно это, а не «файл не найден».
        match connect().await {
            // Демон и правда работает — тоже законный исход.
            Ok(_) => {}
            Err(err) => assert!(
                matches!(err, IpcError::DaemonNotRunning | IpcError::AccessDenied),
                "невнятная ошибка: {err}"
            ),
        }
    }

    #[tokio::test]
    async fn listen_and_connect_meet() {
        // Канал один на систему, поэтому тест и на приём, и на подключение
        // здесь один: два теста, открывающих канал, мешали бы друг другу так
        // же, как мешают два демона.
        let listener = match listen() {
            Ok(listener) => listener,
            // Демон уже занял канал — законный исход на рабочей машине.
            Err(IpcError::AlreadyRunning) => return,
            Err(err) => panic!("канал не открылся: {err}"),
        };

        // Второй слушатель на том же имени обязан получить внятное «уже
        // работает», а не «отказано в доступе».
        assert!(matches!(listen(), Err(IpcError::AlreadyRunning)));

        let client = tokio::spawn(async { connect().await });
        let accepted = listener.accept().await;

        assert!(accepted.is_ok(), "соединение не принято");
        assert!(
            client.await.expect("задача").is_ok(),
            "клиент не подключился"
        );
    }
}
