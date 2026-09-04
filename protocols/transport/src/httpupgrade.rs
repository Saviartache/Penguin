//! `Upgrade` без кадров: то же рукопожатие, что у WebSocket, и голые байты
//! следом.
//!
//! Разница с [`ws`](crate::ws) ровно одна и вся в цене. Рукопожатие
//! одинаковое — тот же `GET` с `Upgrade: websocket`, тот же ответ `101`, — и
//! для промежуточного узла, для nginx и для панели облачного провайдера это
//! неотличимо от WebSocket. А дальше кадров нет: байты идут как есть, без
//! заголовка на каждый кусок и без прохода XOR по всему, что уходит.
//!
//! Отсюда и область применения: там, где путь до сервера свой и ломать поток
//! на кадры некому, `Upgrade` даёт то же самое дешевле. Там, где по дороге
//! стоит что-то, разбирающее WebSocket всерьёз, нужен настоящий
//! [`ws`](crate::ws) — узел, ожидающий кадры и не получивший их, закрывает
//! соединение.
//!
//! # Что здесь сверено, а что нет
//!
//! Рукопожатие взято тем же, что у WebSocket, намеренно: заголовки, которые
//! шлёт браузер, проходят везде, а урезанный набор упирается в первый же
//! обратный прокси, требующий `Sec-WebSocket-Key`. Лишним он не бывает —
//! сервер, которому он не нужен, его просто не читает.
//!
//! Проверка `Sec-WebSocket-Accept` здесь, наоборот, не требуется: сервер без
//! WebSocket его не считает, и требовать его значило бы отвергать рабочие
//! настройки. Остаётся код `101` и `Upgrade` в ответе — то, что отличает
//! прокси от обычной страницы.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::deadline;
use crate::error::{TransportError, TransportResult};
use crate::ws::handshake::{self, Request};

/// Поток поверх соединения, сменившего протокол.
///
/// Обёртки нет: после `101` это и есть поток байт. Байты, пришедшие вместе с
/// ответом, возвращаются отдельно — их надо прочитать раньше сокета.
pub struct Upgraded<S> {
    /// Соединение.
    pub io: S,
    /// Байты, пришедшие следом за ответом.
    pub tail: Vec<u8>,
}

/// Проводит рукопожатие.
pub async fn connect<S>(mut io: S, request: &Request) -> TransportResult<Upgraded<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = handshake::new_key();
    let text = handshake::request_text(request, &key);

    let tail = deadline::handshake("рукопожатие Upgrade", async {
        io.write_all(text.as_bytes()).await?;
        io.flush().await?;
        let (head, tail) = handshake::read_head(&mut io).await?;
        check_response(&head)?;
        Ok::<_, TransportError>(tail)
    })
    .await?;

    Ok(Upgraded { io, tail })
}

/// Проверяет заголовок ответа.
///
/// Без `Sec-WebSocket-Accept`: сервер, не делающий WebSocket, его не считает.
pub fn check_response(head: &str) -> TransportResult<()> {
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| TransportError::malformed("пустой ответ"))?;

    if !status.contains(" 101") {
        return Err(TransportError::malformed(format!(
            "на смену протокола ответили `{}`",
            status.trim()
        )));
    }

    let upgraded = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("upgrade") && !value.trim().is_empty()
        })
    });
    if !upgraded {
        return Err(TransportError::malformed("в ответе нет `Upgrade`"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    #[test]
    fn a_reply_without_the_websocket_accept_still_passes() {
        // Сервер без WebSocket его не считает, и требовать его значило бы
        // отвергать рабочие настройки.
        let head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket";
        check_response(head).expect("ответ верный");
    }

    #[test]
    fn an_ordinary_page_is_told_apart() {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/html";
        let err = check_response(head).expect_err("это не прокси");
        assert!(err.to_string().contains("200"), "{err}");
    }

    #[test]
    fn a_reply_without_upgrade_is_refused() {
        let head = "HTTP/1.1 101 Switching Protocols\r\nServer: nginx";
        assert!(check_response(head).is_err());
    }

    #[tokio::test]
    async fn the_handshake_looks_exactly_like_websocket() {
        // Урезанный набор заголовков упирается в первый же обратный прокси,
        // требующий `Sec-WebSocket-Key`.
        let (client, mut server) = tokio::io::duplex(4096);

        let task =
            tokio::spawn(async move { connect(client, &Request::new("example.com", "/up")).await });

        let mut raw = vec![0u8; 1024];
        let read = server.read(&mut raw).await.unwrap();
        let request = String::from_utf8_lossy(&raw[..read]).into_owned();

        assert!(request.starts_with("GET /up HTTP/1.1\r\n"), "{request}");
        assert!(request.contains("Upgrade: websocket\r\n"), "{request}");
        assert!(request.contains("Connection: Upgrade\r\n"), "{request}");
        assert!(request.contains("Sec-WebSocket-Key: "), "{request}");

        server
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\ntail")
            .await
            .unwrap();

        let upgraded = task.await.unwrap().expect("рукопожатие");
        assert_eq!(upgraded.tail, b"tail");
    }

    #[tokio::test]
    async fn data_goes_through_without_framing() {
        // В этом весь смысл: после `101` байты идут как есть.
        let (client, mut server) = tokio::io::duplex(4096);

        let task = tokio::spawn(async move {
            let mut upgraded = connect(client, &Request::new("example.com", "/up"))
                .await
                .expect("рукопожатие");
            upgraded.io.write_all(b"hello").await.unwrap();
            upgraded.io.flush().await.unwrap();
        });

        let mut raw = vec![0u8; 1024];
        let _ = server.read(&mut raw).await.unwrap();
        server
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
            .await
            .unwrap();

        let mut got = [0u8; 5];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        task.await.unwrap();
    }
}
