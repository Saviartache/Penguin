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

/// Подключается к каналу.
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
        // Путей два: общий у службы и свой у отладочного запуска. Первая
        // ошибка сохраняется — по ней и отвечаем, если не подошёл ни один.
        let mut first = None;
        for path in unix::connect_paths() {
            match connect_at(&path).await {
                Ok(stream) => return Ok(stream),
                Err(err) => first.get_or_insert(err),
            };
        }
        Err(first.unwrap_or(IpcError::DaemonNotRunning))
    }
}

/// Подключается к каналу по указанному пути.
#[cfg(unix)]
pub async fn connect_at(path: &std::path::Path) -> IpcResult<LocalSocketStream> {
    use interprocess::local_socket::{GenericFilePath, ToFsName};

    let name = path
        .to_fs_name::<GenericFilePath>()
        .map_err(|e| IpcError::Transport(format!("имя канала: {e}")))?;

    LocalSocketStream::connect(name).await.map_err(classify)
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

        let connecting = connect_at(&path);
        let accepted = listener.accept().await;

        assert!(accepted.is_ok(), "соединение не принято");
        assert!(connecting.await.is_ok(), "клиент не подключился");

        drop(listener);
        let _ = std::fs::remove_file(&path);
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
        // Канал один на систему, поэтому тест и на приём, и на подключение
        // здесь один: два теста, открывающих канал, мешали бы друг другу так
        // же, как мешают два демона.
        let listener = match listen() {
            Ok(listener) => listener,
            // Демон уже занял канал — законный исход на рабочей машине.
            Err(IpcError::AlreadyRunning) => return,
            Err(err) => panic!("канал не открылся: {err}"),
        };

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
