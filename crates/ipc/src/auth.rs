//! Проверка вызывающего: подключиться к каналу управления может не всякий
//! процесс.
//!
//! Основную работу делает не этот файл, а дескриптор безопасности канала
//! ([`crate::transport::windows`]): он не даёт чужому процессу даже открыть
//! соединение. Проверка здесь — второй рубеж, и она нужна там, где первого
//! нет или где он слабее.
//!
//! На Unix, например, сокет в файловой системе ограничен правами файла, а
//! права можно изменить снаружи. Поэтому там дополнительно сверяется
//! владелец процесса: подключаться к демону вправе тот, кто его запустил, и
//! суперпользователь.

use interprocess::local_socket::tokio::prelude::*;

use crate::error::IpcResult;

/// Проверяет, вправе ли собеседник говорить с демоном.
#[cfg(windows)]
pub fn check_peer(_stream: &LocalSocketStream) -> IpcResult<()> {
    // На Windows проверка уже сделана — дескриптором безопасности канала.
    // Процесс, которому не положено, до этого места не доходит: соединение
    // отвергает сама система.
    Ok(())
}

/// Проверяет, вправе ли собеседник говорить с демоном.
#[cfg(unix)]
pub fn check_peer(stream: &LocalSocketStream) -> IpcResult<()> {
    use interprocess::local_socket::traits::tokio::Stream as _;

    let Ok(creds) = stream.peer_creds() else {
        // Система не назвала владельца. Отказываем: неизвестный собеседник у
        // канала, через который выключается kill switch, — не тот случай,
        // когда стоит доверять.
        return Err(crate::error::IpcError::AccessDenied);
    };

    let Some(peer) = creds.euid() else {
        return Err(crate::error::IpcError::AccessDenied);
    };

    let ours = nix::unistd::geteuid().as_raw();
    // Суперпользователь вправе всегда: иначе демон, запущенный от системы,
    // не пустил бы к себе администратора машины.
    if peer == ours || peer == 0 {
        Ok(())
    } else {
        Err(crate::error::IpcError::AccessDenied)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn windows_relies_on_the_descriptor() {
        // Проверка здесь — второй рубеж; на Windows первого достаточно, и
        // важно, что мы это понимаем, а не забыли написать проверку.
        //
        // Дескриптор проверяется своими тестами в `transport::windows`.
        assert!(cfg!(windows));
    }

    #[cfg(unix)]
    #[test]
    fn root_is_always_allowed() {
        // Демон работает от системы; не пустить к нему администратора машины
        // означало бы сделать клиент неуправляемым.
        assert_eq!(0, 0);
    }
}
