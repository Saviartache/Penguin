//! Проверка собеседника. На Windows канал защищает его дескриптор безопасности
//! (`transport::windows`), на Unix права каталога дополняются сверкой peer-uid.
//!
//! Допускаются root, администраторы, UID самого демона и один UID рабочего
//! стола, одобренный повышенным помощником.

use crate::error::IpcResult;
use crate::transport::Stream;

/// Проверяет, вправе ли собеседник говорить с демоном.
#[cfg(windows)]
pub fn check_peer(_stream: &Stream) -> IpcResult<()> {
    Ok(())
}

/// Проверяет, вправе ли собеседник говорить с демоном.
#[cfg(unix)]
pub fn check_peer(stream: &Stream) -> IpcResult<()> {
    use crate::error::IpcError;

    // Неизвестный собеседник у канала с kill switch не допускается.
    let peer = stream
        .peer_cred()
        .map_err(|_| IpcError::AccessDenied)?
        .uid();

    let ours = nix::unistd::geteuid().as_raw();
    let administrator = crate::transport::unix::is_administrator(peer);
    let approved = if ours == 0 && peer != 0 && !administrator {
        crate::controller::approved()?
    } else {
        None
    };
    if crate::policy::permits(peer, ours, approved, administrator) {
        Ok(())
    } else {
        Err(IpcError::AccessDenied)
    }
}

/// Проверяет euid сервера до отправки запросов и секретов.
#[cfg(unix)]
pub(crate) fn check_server(stream: &Stream, expected: u32) -> IpcResult<()> {
    // Нет uid — отказ, а не повод доверять пути.
    let peer = stream.peer_cred().ok().map(|creds| creds.uid());
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
        const { assert!(cfg!(windows)) };
    }

    #[cfg(unix)]
    #[test]
    fn root_is_an_administrator() {
        assert!(crate::transport::unix::is_administrator(0));
    }
}
