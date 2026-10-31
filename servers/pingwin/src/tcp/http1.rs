//! Прикрытие по HTTP/1.1: кто пришёл без `h2`, видит тот же сайт, а не обрыв.
//! Один запрос на соединение (`Connection: close`) — так отвечают и обычные сайты.

use std::path::Path;
use std::time::Duration;

use http::{Method, Request, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::cover;

/// Наибольшая голова запроса; длиннее — `431`.
const MAX_HEAD: usize = 16 * 1024;

/// Сколько ждать голову запроса.
const HEAD_LIMIT: Duration = Duration::from_secs(10);

const BAD_REQUEST: &str = "<html><head><title>400 Bad Request</title></head>\
<body><h1>400 Bad Request</h1></body></html>\n";

/// Отвечает на один запрос как сайт из каталога `root`.
pub(crate) async fn serve<S>(root: Option<&Path>, mut io: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = match tokio::time::timeout(HEAD_LIMIT, read_head(&mut io)).await {
        Ok(Head::Complete(head)) => head,
        Ok(Head::TooLong) => {
            let status = StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE;
            respond(&mut io, status, "text/html", BAD_REQUEST.as_bytes(), false).await;
            return;
        }
        Ok(Head::Closed) | Err(_) => return,
    };
    let Some(request) = parse(&head) else {
        let status = StatusCode::BAD_REQUEST;
        respond(&mut io, status, "text/html", BAD_REQUEST.as_bytes(), false).await;
        return;
    };
    let (status, content_type, body) = cover::answer(root, &request).await;
    let head_only = request.method() == Method::HEAD;
    respond(&mut io, status, content_type, &body, head_only).await;
}

/// Чем кончилось чтение головы.
#[derive(Debug, PartialEq, Eq)]
enum Head {
    Complete(Vec<u8>),
    TooLong,
    Closed,
}

async fn read_head<S: AsyncRead + Unpin>(io: &mut S) -> Head {
    let mut head = Vec::with_capacity(1024);
    let mut buffer = [0u8; 2048];
    loop {
        match io.read(&mut buffer).await {
            Ok(0) | Err(_) => return Head::Closed,
            Ok(read) => head.extend_from_slice(&buffer[..read]),
        }
        if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            head.truncate(end);
            return Head::Complete(head);
        }
        if head.len() > MAX_HEAD {
            return Head::TooLong;
        }
    }
}

/// Строка запроса `МЕТОД ЦЕЛЬ HTTP/1.x`; заголовки сайту не нужны.
fn parse(head: &[u8]) -> Option<Request<()>> {
    let line = head.split(|&byte| byte == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
    let mut parts = line.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return None;
    }
    Request::builder().method(method).uri(target).body(()).ok()
}

/// Голова ответа.
fn status_head(status: StatusCode, content_type: &str, len: usize) -> String {
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\n\
         Connection: close\r\n\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or_default(),
    )
}

async fn respond<S>(
    io: &mut S,
    status: StatusCode,
    content_type: &str,
    body: &[u8],
    head_only: bool,
) where
    S: AsyncWrite + Unpin,
{
    let mut out = status_head(status, content_type, body.len()).into_bytes();
    if !head_only {
        out.extend_from_slice(body);
    }
    let sent = async {
        io.write_all(&out).await?;
        io.shutdown().await
    };
    if let Err(err) = sent.await {
        tracing::trace!(%err, "ответ HTTP/1.1 не ушёл");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_browser_request_line_is_read() {
        let request =
            parse(b"GET /css/site.css HTTP/1.1\r\nHost: example.com").expect("разбирается");
        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.uri().path(), "/css/site.css");
    }

    #[test]
    fn http2_without_alpn_and_garbage_are_bad_requests() {
        for head in [
            &b"PRI * HTTP/2.0"[..],
            b"GET /",
            b"GET / HTTP/1.1 extra",
            b"\xff\xfe",
            b"",
        ] {
            assert!(parse(head).is_none(), "{head:?}");
        }
    }

    #[test]
    fn the_answer_says_how_long_it_is_and_closes() {
        let head = status_head(StatusCode::OK, "text/html", 14);
        assert_eq!(
            head,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 14\r\n\
             Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn the_head_ends_at_the_blank_line_and_has_a_limit() {
        let mut short = &b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"[..];
        assert_eq!(
            read_head(&mut short).await,
            Head::Complete(b"GET / HTTP/1.1\r\nHost: x".to_vec())
        );
        let long = vec![b'a'; MAX_HEAD + 4096];
        assert_eq!(read_head(&mut &long[..]).await, Head::TooLong);
        assert_eq!(read_head(&mut &b"GET /"[..]).await, Head::Closed);
    }
}
