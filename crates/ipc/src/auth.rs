//! Проверка вызывающего: подключиться к каналу управления может не всякий
//! процесс.
//!
//! Основную работу делает не этот файл, а дескриптор безопасности канала
//! (`transport::windows`): он не даёт чужому процессу даже открыть
//! соединение. Проверка здесь — второй рубеж, и она нужна там, где первого
//! нет или где он слабее.
//!
//! На Unix, например, сокет в файловой системе ограничен правами каталога, а
//! права можно изменить снаружи. Поэтому там дополнительно сверяется
//! владелец процесса.
//!
//! Unix admits root, administrators, the daemon's own UID, and the one desktop
//! UID explicitly approved by an elevated helper for the root service.

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
    // Суперпользователь и тот, кто демона запустил, — вправе всегда.
    // Администратор машины — тоже: служба работает под системой, окно под
    // человеком, и без этого человек не смог бы нажать даже «Подключить».
    // Нового доступа это не даёт: администратор и так может стать
    // суперпользователем.
    let administrator = crate::transport::unix::is_administrator(peer);
    let approved = if ours == 0 && peer != 0 && !administrator {
        crate::controller::approved()?
    } else {
        None
    };
    if crate::policy::permits(peer, ours, approved, administrator) {
        Ok(())
    } else {
        Err(crate::error::IpcError::AccessDenied)
    }
}

/// Verifies the Unix server UID before any request or secret is sent.
#[cfg(unix)]
pub(crate) fn check_server(stream: &LocalSocketStream, expected: u32) -> IpcResult<()> {
    // interprocess exposes SO_PEERCRED.uid on Linux and LOCAL_PEERCRED.cr_uid
    // on macOS. A missing EUID is a denial, never a reason to trust the path.
    let peer = stream.peer_creds().ok().and_then(|creds| creds.euid());
    if crate::policy::trusts_server(peer, expected) {
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
        const { assert!(cfg!(windows)) };
    }

    #[cfg(unix)]
    #[test]
    fn root_is_an_administrator() {
        // Демон работает от системы; не пустить к нему администратора машины
        // означало бы сделать клиент неуправляемым из окна.
        assert!(crate::transport::unix::is_administrator(0));
    }
}
