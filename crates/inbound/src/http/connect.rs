//! Метод CONNECT и туннелирование поверх него.
//!
//! ```text
//! клиент → CONNECT example.com:443 HTTP/1.1
//!          Host: example.com:443
//!
//! сервер → HTTP/1.1 200 Connection established
//! ```
//!
//! Дальше идут просто байты. Обычные запросы (`GET http://…`) не поддерживаются:
//! для них пришлось бы переписывать заголовки.

use penguin_core::address::SocketAddress;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::error::{InboundError, InboundResult};

/// Наибольшая длина строки запроса и заголовка.
const MAX_LINE: usize = 8 * 1024;

/// Наибольшее число заголовков.
const MAX_HEADERS: usize = 64;

/// Читает запрос `CONNECT` и возвращает адрес назначения.
pub async fn read_request<S>(stream: &mut BufReader<S>) -> InboundResult<SocketAddress>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::with_capacity(256);
    read_line(stream, &mut line).await?;
    let target = parse_request_line(&line)?;

    // Заголовки вычитываются, иначе уедут в тоннель как данные.
    for _ in 0..MAX_HEADERS {
        read_line(stream, &mut line).await?;
        if line.is_empty() {
            return Ok(target);
        }
    }
    Err(InboundError::BadAddress(
        "слишком много заголовков".to_owned(),
    ))
}

/// Разбирает `CONNECT host[:port] HTTP/1.1`; порт по умолчанию 443 (CONNECT нужен ради TLS).
fn parse_request_line(line: &[u8]) -> InboundResult<SocketAddress> {
    let text = std::str::from_utf8(line)
        .map_err(|_| InboundError::BadAddress("строка не в UTF-8".to_owned()))?;
    let mut parts = text.split_whitespace();

    let method = parts.next().unwrap_or_default();
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(InboundError::BadAddress(format!(
            "поддерживается только CONNECT, получен `{method}`"
        )));
    }

    let bad = || InboundError::BadAddress(text.to_owned());
    let target = parts.next().ok_or_else(bad)?;
    if target.contains(':') {
        target.parse().map_err(|_| bad())
    } else {
        format!("{target}:443").parse().map_err(|_| bad())
    }
}

/// Читает строку в `line` без перевода строки; длина ограничена `MAX_LINE`.
async fn read_line<S>(stream: &mut BufReader<S>, line: &mut Vec<u8>) -> InboundResult<()>
where
    S: AsyncRead + Unpin,
{
    line.clear();
    loop {
        let available = stream.fill_buf().await?;
        if available.is_empty() {
            return Err(InboundError::Io(std::io::Error::from(
                std::io::ErrorKind::UnexpectedEof,
            )));
        }

        let (chunk, consumed, done) = match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => (&available[..index], index + 1, true),
            None => (available, available.len(), false),
        };
        line.extend_from_slice(chunk);
        stream.consume(consumed);

        if line.len() > MAX_LINE {
            return Err(InboundError::BadAddress(
                "слишком длинная строка".to_owned(),
            ));
        }
        if done {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(());
        }
    }
}

/// Отвечает, что тоннель установлен.
pub async fn reply_established<S>(stream: &mut S) -> InboundResult<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    Ok(())
}

/// Отвечает отказом.
pub async fn reply_failure<S>(stream: &mut S, status: u16, reason: &str) -> InboundResult<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let body =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(body.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    async fn parse(request: &str) -> InboundResult<SocketAddress> {
        let mut reader = BufReader::new(std::io::Cursor::new(request.as_bytes().to_vec()));
        read_request(&mut reader).await
    }

    #[tokio::test]
    async fn reads_connect() {
        let target = parse("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .expect("разбирается");
        assert_eq!(target, SocketAddress::domain("example.com", 443));
    }

    #[tokio::test]
    async fn defaults_the_port_to_443() {
        let target = parse("CONNECT example.com HTTP/1.1\r\n\r\n")
            .await
            .expect("разбирается");
        assert_eq!(target.port, 443);
    }

    #[tokio::test]
    async fn rejects_plain_get() {
        assert!(
            parse("GET http://example.com/ HTTP/1.1\r\n\r\n")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn consumes_headers_before_the_tunnel() {
        let request = "CONNECT example.com:443 HTTP/1.1\r\nHost: x\r\nProxy-Connection: keep-alive\r\n\r\nDATA";
        let mut reader = BufReader::new(std::io::Cursor::new(request.as_bytes().to_vec()));
        read_request(&mut reader).await.expect("разбирается");

        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.expect("хвост");
        assert_eq!(rest, b"DATA");
    }

    #[tokio::test]
    async fn rejects_endless_headers() {
        let mut request = String::from("CONNECT example.com:443 HTTP/1.1\r\n");
        for index in 0..MAX_HEADERS + 10 {
            request.push_str(&format!("X-Header-{index}: value\r\n"));
        }
        request.push_str("\r\n");
        assert!(parse(&request).await.is_err());
    }

    #[tokio::test]
    async fn writes_established_reply() {
        let (mut ours, mut theirs) = tokio::io::duplex(256);
        reply_established(&mut ours).await.expect("записано");
        let mut buf = vec![0u8; 39];
        theirs.read_exact(&mut buf).await.expect("прочитано");
        assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200"));
    }
}
