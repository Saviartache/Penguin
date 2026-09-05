//! Транспорт канала управления.
//!
//! На Windows это именованный канал, на остальных системах — сокет в
//! файловой системе. Общего у них ровно столько, сколько нужно: имя, по
//! которому обе стороны находят друг друга, и поток байт.

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
pub use unix::connect_service;
#[cfg(windows)]
pub use windows::connect_service;

use interprocess::local_socket::tokio::prelude::*;

use crate::error::{IpcError, IpcResult};

/// Имя канала управления.
///
/// Одно на всю систему: демон один, и клиентов у него сколько угодно.
pub const CHANNEL_NAME: &str = "penguin-control.sock";

/// Открывает канал на приём.
///
/// Доступ к каналу ограничивается сразу: канал с умолчанием открыт шире, чем
/// нужно, а через него можно выключить kill switch. На Windows это дескриптор
/// безопасности (`transport::windows`), на остальных системах — права каталога
/// (`transport::unix`). Ссылками соседи не оформлены намеренно: каждого из них
/// видно только в сборке под свою систему.
pub fn listen() -> IpcResult<LocalSocketListener> {
    #[cfg(windows)]
    {
        use interprocess::local_socket::{GenericNamespaced, ListenerOptions, ToNsName};

        let name = CHANNEL_NAME
            .to_ns_name::<GenericNamespaced>()
            .map_err(|e| IpcError::Transport(format!("имя канала: {e}")))?;

        let options = windows::secure(ListenerOptions::new().name(name))?;
        options.create_tokio().map_err(|e| match e.kind() {
            // Windows отвечает «отказано в доступе», а не «занято», когда
            // канал с таким именем уже создан другим процессом с иным
            // дескриптором безопасности. Создать именованный канал в своём
            // пространстве имён обычный пользователь может всегда, так что
            // другой причины для отказа тут практически не бывает — и
            // сообщать про доступ значило бы сбивать с толку.
            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied => {
                IpcError::AlreadyRunning
            }
            _ => IpcError::Transport(format!("не удалось открыть канал управления: {e}")),
        })
    }
    #[cfg(unix)]
    {
        listen_at(&unix::listen_path())
    }
}

/// Открывает канал по указанному пути.
///
/// Отдельно от [`listen`] ради тестов: канал один на систему, и проверять его
/// на настоящем пути значило бы драться с работающей службой.
#[cfg(unix)]
pub fn listen_at(path: &std::path::Path) -> IpcResult<LocalSocketListener> {
    use interprocess::local_socket::{GenericFilePath, ListenerOptions, ToFsName};

    unix::prepare(path)?;
    // Сокет, оставшийся от упавшего демона, файловую систему переживает, а
    // привязку к себе не отдаёт: без уборки служба больше не поднимется.
    unix::clear_stale(path)?;
    unix::restrict(path)?;

    let name = path
        .to_fs_name::<GenericFilePath>()
        .map_err(|e| IpcError::Transport(format!("имя канала: {e}")))?;

    let listener = ListenerOptions::new()
        .name(name)
        .create_tokio()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AddrInUse => IpcError::AlreadyRunning,
            std::io::ErrorKind::PermissionDenied => IpcError::AccessDenied,
            _ => IpcError::Transport(format!("не удалось открыть канал управления: {e}")),
        })?;

    unix::secure(path)?;
    Ok(listener)
}

/// Connects to the channel, allowing a per-user foreground fallback on Unix.
///
/// Use [`connect_service`] for GUI connections and service readiness.
pub async fn connect() -> IpcResult<LocalSocketStream> {
    #[cfg(windows)]
    {
        use interprocess::local_socket::{GenericNamespaced, ToNsName};

        let name = CHANNEL_NAME
            .to_ns_name::<GenericNamespaced>()
            .map_err(|e| IpcError::Transport(format!("имя канала: {e}")))?;
        LocalSocketStream::connect(name).await.map_err(classify)
    }
    #[cfg(unix)]
    {
        // Foreground fallback is only for an absent service, never for a
        // denied or untrusted system endpoint.
        for path in unix::connect_paths() {
            match connect_at(&path).await {
                Ok(stream) => return Ok(stream),
                Err(IpcError::DaemonNotRunning) => continue,
                Err(err) => return Err(err),
            };
        }
        Err(IpcError::DaemonNotRunning)
    }
}

/// Connects to a Unix endpoint and verifies its server's effective UID.
///
/// The system endpoint requires root; explicit/foreground paths require the
/// current effective UID. Socket-file ownership is not server authentication.
#[cfg(unix)]
pub async fn connect_at(path: &std::path::Path) -> IpcResult<LocalSocketStream> {
    use interprocess::local_socket::{GenericFilePath, ToFsName};

    let name = path
        .to_fs_name::<GenericFilePath>()
        .map_err(|e| IpcError::Transport(format!("имя канала: {e}")))?;

    let stream = LocalSocketStream::connect(name).await.map_err(classify)?;
    let expected = if unix::is_system_path(path) {
        0
    } else {
        nix::unistd::geteuid().as_raw()
    };
    crate::auth::check_server(&stream, expected)?;
    Ok(stream)
}

/// Переводит отказ подключения в понятную ошибку.
fn classify(err: std::io::Error) -> IpcError {
    match err.kind() {
        // Канала нет — демон не запущен. Самая частая причина, и сообщение
        // должно говорить именно это, а не «файл не найден».
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            IpcError::DaemonNotRunning
        }
        std::io::ErrorKind::PermissionDenied => IpcError::AccessDenied,
        _ => IpcError::Transport(format!("не удалось подключиться к демону: {err}")),
    }
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

    #[test]
    fn connection_errors_are_classified_without_contacting_a_service() {
        use std::io::ErrorKind;
        for kind in [ErrorKind::NotFound, ErrorKind::ConnectionRefused] {
            assert!(matches!(classify(kind.into()), IpcError::DaemonNotRunning));
        }
        assert!(matches!(
            classify(ErrorKind::PermissionDenied.into()),
            IpcError::AccessDenied
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn listen_and_connect_meet() {
        // На своём пути, а не на общем: тест не должен ни драться с
        // работающей службой, ни требовать прав.
        let path = std::env::temp_dir()
            .join(format!("penguin-test-{}", std::process::id()))
            .join("control.sock");
        let listener = listen_at(&path).expect("канал открылся");

        // Второй слушатель на том же имени обязан получить внятное «уже
        // работает», а не «отказано в доступе».
        assert!(matches!(listen_at(&path), Err(IpcError::AlreadyRunning)));

        // Drain the live-listener probe, then accept the actual client.
        drop(listener.accept().await.expect("probe"));
        let (connected, accepted) = tokio::join!(connect_at(&path), listener.accept());
        let connected = connected.expect("client connected");
        let accepted = accepted.expect("client accepted");
        let uid = nix::unistd::geteuid().as_raw();
        assert_eq!(connected.peer_creds().unwrap().euid(), Some(uid));
        assert_eq!(accepted.peer_creds().unwrap().euid(), Some(uid));
        assert!(crate::auth::check_peer(&accepted).is_ok());
        assert!(crate::auth::check_server(&connected, uid).is_ok());
        assert!(matches!(
            crate::auth::check_server(&connected, uid ^ 1),
            Err(IpcError::AccessDenied)
        ));

        drop(listener);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().expect("directory"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_socket_left_by_a_dead_daemon_does_not_block_the_next_one() {
        // Файл сокета переживает смерть демона, а привязку к себе не отдаёт:
        // без уборки служба больше не поднялась бы никогда.
        let path = std::env::temp_dir()
            .join(format!("penguin-stale-{}", std::process::id()))
            .join("control.sock");
        std::fs::create_dir_all(path.parent().expect("каталог")).expect("каталог создан");

        // Так выглядит след убитого демона: сокет в файловой системе есть, а
        // слушать его некому. Стандартный слушатель файл за собой не убирает —
        // ровно это и происходит при аварийном завершении.
        drop(std::os::unix::net::UnixListener::bind(&path).expect("сокет создан"));
        assert!(path.exists(), "файл сокета должен остаться");

        let listener = listen_at(&path).expect("канал открылся заново");
        drop(listener);
        let _ = std::fs::remove_dir_all(path.parent().expect("каталог"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn listen_and_connect_meet() {
        use interprocess::TryClone;
        use interprocess::local_socket::{GenericNamespaced, ListenerOptions, ToNsName};
        let label = format!("penguin-transport-test-{}", std::process::id());
        let name = label.to_ns_name::<GenericNamespaced>().unwrap();
        let options = windows::secure(ListenerOptions::new().name(name.clone())).unwrap();
        let listener = options.try_clone().unwrap().create_tokio().unwrap();
        assert!(options.create_tokio().is_err());
        let (connected, accepted) =
            tokio::join!(LocalSocketStream::connect(name), listener.accept());
        assert!(connected.is_ok());
        assert!(accepted.is_ok());
    }
}
