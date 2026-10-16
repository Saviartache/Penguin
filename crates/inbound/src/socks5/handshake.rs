//! Согласование версии и метода аутентификации.
//!
//! ```text
//! клиент → 0x05 NMETHODS METHODS…
//! сервер → 0x05 METHOD   (0x00 без проверки, 0x02 логин и пароль, 0xFF отказ)
//! ```

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{InboundError, InboundResult};

/// Версия протокола.
pub const VERSION: u8 = 0x05;

/// Без проверки.
pub const METHOD_NONE: u8 = 0x00;
/// Логин и пароль (RFC 1929).
pub const METHOD_USERPASS: u8 = 0x02;
/// Ничего из предложенного не подходит.
pub const METHOD_UNACCEPTABLE: u8 = 0xFF;

/// Что делать дальше.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chosen {
    /// Приступать к запросу.
    NoAuth,
    /// Сначала логин и пароль.
    UserPass,
}

/// Согласовывает способ проверки.
///
/// При `require_auth` вариант без проверки не принимается, даже если клиент его предложил.
pub async fn negotiate<S>(stream: &mut S, require_auth: bool) -> InboundResult<Chosen>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let [version, count] = head;
    // Сюда попадает и HTTP-клиент, постучавшийся не в тот порт.
    if version != VERSION {
        return Err(InboundError::NotSocks5(version));
    }

    let mut buf = [0u8; 255];
    let methods = &mut buf[..usize::from(count)];
    stream.read_exact(methods).await?;

    let wanted = if require_auth {
        METHOD_USERPASS
    } else {
        METHOD_NONE
    };

    if methods.contains(&wanted) {
        stream.write_all(&[VERSION, wanted]).await?;
        return Ok(if require_auth {
            Chosen::UserPass
        } else {
            Chosen::NoAuth
        });
    }

    // Без отказа клиент ждёт до тайм-аута.
    stream.write_all(&[VERSION, METHOD_UNACCEPTABLE]).await?;
    Err(InboundError::NoAcceptableAuth)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use tokio::io::duplex;

    use super::*;

    async fn run(client_bytes: &[u8], require_auth: bool) -> (InboundResult<Chosen>, Vec<u8>) {
        let (mut ours, mut theirs) = duplex(1024);
        theirs.write_all(client_bytes).await.expect("запись");

        let result = negotiate(&mut ours, require_auth).await;

        let mut reply = vec![0u8; 2];
        let read = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            theirs.read_exact(&mut reply),
        )
        .await;
        if read.is_err() || read.is_ok_and(|r| r.is_err()) {
            reply.clear();
        }
        (result, reply)
    }

    #[tokio::test]
    async fn picks_no_auth_when_password_not_required() {
        let (result, reply) = run(&[VERSION, 1, METHOD_NONE], false).await;
        assert_eq!(result.expect("согласовано"), Chosen::NoAuth);
        assert_eq!(reply, vec![VERSION, METHOD_NONE]);
    }

    #[tokio::test]
    async fn picks_userpass_when_password_required() {
        let (result, reply) = run(&[VERSION, 2, METHOD_NONE, METHOD_USERPASS], true).await;
        assert_eq!(result.expect("согласовано"), Chosen::UserPass);
        assert_eq!(reply, vec![VERSION, METHOD_USERPASS]);
    }

    #[tokio::test]
    async fn refuses_when_client_cannot_authenticate() {
        let (result, reply) = run(&[VERSION, 1, METHOD_NONE], true).await;
        assert!(matches!(result, Err(InboundError::NoAcceptableAuth)));
        assert_eq!(reply, vec![VERSION, METHOD_UNACCEPTABLE]);
    }

    #[tokio::test]
    async fn rejects_wrong_version() {
        // `G` из `GET`: адрес SOCKS-прокси дали как HTTP.
        let mut reader = Cursor::new(vec![b'G', 1, 0]);
        let (mut stream, _) = duplex(16);
        let _ = &mut stream;
        let result = negotiate(&mut reader_as_stream(&mut reader), false).await;
        assert!(matches!(result, Err(InboundError::NotSocks5(b'G'))));
    }

    /// Курсор умеет только читать; для `negotiate` нужен и писатель.
    fn reader_as_stream(cursor: &mut Cursor<Vec<u8>>) -> impl AsyncRead + AsyncWrite + Unpin + '_ {
        tokio::io::join(cursor, tokio::io::sink())
    }
}
