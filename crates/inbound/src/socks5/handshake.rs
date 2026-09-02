//! Согласование версии и метода аутентификации.
//!
//! ```text
//! клиент → 0x05 NMETHODS METHODS…
//! сервер → 0x05 METHOD
//! ```
//!
//! `METHOD` — выбранный способ: `0x00` без проверки, `0x02` логин и пароль,
//! `0xFF` «ничего из предложенного не подходит», после чего соединение
//! закрывается.

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
/// `require_auth` — нужен ли пароль. Когда пароль задан, вариант без проверки
/// не предлагается вовсе: иначе клиент выберет его, и пароль окажется
/// украшением.
pub async fn negotiate<S>(stream: &mut S, require_auth: bool) -> InboundResult<Chosen>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let version = stream.read_u8().await?;
    if version != VERSION {
        // Сюда попадает и HTTP-клиент, постучавшийся не в тот порт: его
        // первый байт — буква из `GET` или `CONNECT`.
        return Err(InboundError::NotSocks5(version));
    }

    let count = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; count];
    stream.read_exact(&mut methods).await?;

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

    // Отказ полагается отправить: без него клиент ждёт ответа до тайм-аута и
    // сообщает пользователю «прокси не отвечает» вместо «прокси отказал».
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
        // Вариант без проверки не выбирается, хотя клиент его предложил, —
        // иначе заданный пароль ничего бы не значил.
        assert_eq!(reply, vec![VERSION, METHOD_USERPASS]);
    }

    #[tokio::test]
    async fn refuses_when_client_cannot_authenticate() {
        let (result, reply) = run(&[VERSION, 1, METHOD_NONE], true).await;
        assert!(matches!(result, Err(InboundError::NoAcceptableAuth)));
        // Отказ обязан быть отправлен, иначе клиент ждёт до тайм-аута.
        assert_eq!(reply, vec![VERSION, METHOD_UNACCEPTABLE]);
    }

    #[tokio::test]
    async fn rejects_wrong_version() {
        // `G` из `GET` — обычный случай, когда браузеру дали адрес прокси
        // как HTTP-прокси.
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
