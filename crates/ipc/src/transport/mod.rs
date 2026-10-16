//! Транспорт канала управления: именованный канал на Windows, сокет в
//! файловой системе на остальных системах.

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
pub use unix::{Listener, Stream, connect_at, connect_service, listen_at};
#[cfg(windows)]
pub use windows::{Listener, Stream, connect_service};

use crate::error::{IpcError, IpcResult};

/// Имя канала управления; одно на систему.
pub const CHANNEL_NAME: &str = "penguin-control.sock";

/// Открывает канал на приём. Доступ ограничен сразу: через канал выключается kill switch.
pub fn listen() -> IpcResult<Listener> {
    #[cfg(windows)]
    {
        windows::listen()
    }
    #[cfg(unix)]
    {
        listen_at(&unix::listen_path())
    }
}

/// Подключается к каналу; на Unix допускает запасной канал пользователя.
///
/// Для GUI и проверки готовности службы — [`connect_service`].
pub async fn connect() -> IpcResult<Stream> {
    #[cfg(windows)]
    {
        windows::connect().await
    }
    #[cfg(unix)]
    {
        // Запасной канал — только когда службы нет, не при отказе в доступе.
        for path in unix::connect_paths() {
            match connect_at(&path).await {
                Err(IpcError::DaemonNotRunning) => {}
                other => return other,
            }
        }
        Err(IpcError::DaemonNotRunning)
    }
}

/// Переводит отказ подключения в понятную ошибку.
fn classify(err: std::io::Error) -> IpcError {
    match err.kind() {
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
        // Имя знают обе стороны.
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
        // Свой путь: не драться с работающей службой и не требовать прав.
        let path = std::env::temp_dir()
            .join(format!("penguin-test-{}", std::process::id()))
            .join("control.sock");
        let mut listener = listen_at(&path).expect("канал открылся");

        assert!(matches!(listen_at(&path), Err(IpcError::AlreadyRunning)));

        // Проба живого слушателя стоит в очереди принятия.
        drop(listener.accept().await.expect("probe"));
        let (connected, accepted) = tokio::join!(connect_at(&path), listener.accept());
        let connected = connected.expect("client connected");
        let accepted = accepted.expect("client accepted");
        let uid = nix::unistd::geteuid().as_raw();
        assert_eq!(connected.peer_cred().unwrap().uid(), uid);
        assert_eq!(accepted.peer_cred().unwrap().uid(), uid);
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
        let path = std::env::temp_dir()
            .join(format!("penguin-stale-{}", std::process::id()))
            .join("control.sock");
        std::fs::create_dir_all(path.parent().expect("каталог")).expect("каталог создан");

        // След убитого демона: файл сокета есть, слушателя нет.
        drop(std::os::unix::net::UnixListener::bind(&path).expect("сокет создан"));
        assert!(path.exists(), "файл сокета должен остаться");

        let listener = listen_at(&path).expect("канал открылся заново");
        drop(listener);
        let _ = std::fs::remove_dir_all(path.parent().expect("каталог"));
    }
}
