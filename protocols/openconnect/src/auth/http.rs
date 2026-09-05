//! Один запрос POST на своё TLS-соединение.
//!
//! `openconnect` (`auth.c`) ведёт весь обмен формами на одном соединении с
//! удержанием (keep-alive). Здесь — проще: каждый POST открывает **новое**
//! TLS-соединение и закрывается сам (`Connection: close`). Раундов обычно
//! один-два, и цена лишнего рукопожатия TLS — доли секунды один раз при
//! входе, а не на каждый пакет. Взамен не нужно ни удержания соединения, ни
//! `Transfer-Encoding: chunked`, ни счёта, сколько запросов ещё влезет в один
//! сокет, — старую часть протокола (HTTP/1.1 keep-alive) можно не писать
//! вовсе, читая тело до конца соединения, если сервер не назвал длину.
//!
//! Заголовки запроса и их порядок — из `openconnect/http.c`
//! (`do_https_request`, `http_common_headers`) и `cstp.c`
//! (`cstp_common_headers`, поля вроде `X-Aggregate-Auth`).

use penguin_core::address::Address;
use penguin_proto::connect;
use penguin_proto::dialer::Dialer;
use penguin_transport::deadline;
use penguin_transport::tls::TlsClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{OpenConnectError, OpenConnectResult};
use crate::head::{self, Head};

/// Отправляет `POST` с телом XML и возвращает разобранный ответ вместе с
/// телом.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn post(
    dialer: &dyn Dialer,
    tls: &TlsClient,
    host: &Address,
    port: u16,
    host_header: &str,
    user_agent: &str,
    path: &str,
    cookie: Option<&str>,
    body: &str,
) -> OpenConnectResult<(Head, Vec<u8>)> {
    deadline::handshake("вход OpenConnect", async {
        // `connect::dial` говорит на общем языке `ProtocolError`: это ниже по
        // стеку, чем крейт протокола, и о ошибках, отдельных для XML или
        // формата ответа, разумеется не знает. Здесь его ошибка становится
        // здешней «связь потеряна» — обе стороны сходятся в том, что
        // повторить стоит.
        let plain = connect::dial(dialer, host, port)
            .await
            .map_err(|e| OpenConnectError::disconnected(e.to_string()))?;
        let mut secure = tls.connect(plain).await?;

        let mut request = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host_header}\r\n\
             User-Agent: {user_agent}\r\n\
             Accept: */*\r\n\
             Accept-Encoding: identity\r\n"
        );
        if let Some(cookie) = cookie {
            request.push_str(&format!("Cookie: {cookie}\r\n"));
        }
        request.push_str(&format!(
            "Content-Type: application/xml; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {body}",
            body.len()
        ));

        secure.write_all(request.as_bytes()).await?;
        secure.flush().await?;

        let (head, tail) = head::read(&mut secure).await?;
        let body = read_body(&mut secure, &head, tail).await?;
        Ok((head, body))
    })
    .await
}

/// Дочитывает тело: по `Content-Length`, если он назван, иначе до конца
/// соединения — им и сигнализируется конец тела при `Connection: close`.
async fn read_body<S>(io: &mut S, head: &Head, mut buffer: Vec<u8>) -> OpenConnectResult<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    if let Some(len) = head.header("Content-Length") {
        let len: usize = len.parse().map_err(|_| {
            OpenConnectError::malformed(format!("`Content-Length: {len}` не число"))
        })?;
        if buffer.len() > len {
            buffer.truncate(len);
            return Ok(buffer);
        }
        let mut rest = vec![0u8; len - buffer.len()];
        io.read_exact(&mut rest).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                OpenConnectError::disconnected("тело ответа короче заявленной длины")
            } else {
                OpenConnectError::Io(e)
            }
        })?;
        buffer.extend_from_slice(&rest);
        return Ok(buffer);
    }

    io.read_to_end(&mut buffer).await?;
    Ok(buffer)
}

/// Значение именованной куки из заголовков `Set-Cookie`.
///
/// `ocserv` при успехе шлёт куку `webvpn`, а не поле в теле XML
/// (`worker-auth.c: post_common_handler`) — её и ищет вызывающий код.
pub(crate) fn cookie(head: &Head, name: &str) -> Option<String> {
    head.headers_named("Set-Cookie").find_map(|value| {
        let (pair, _rest) = value.split_once(';').unwrap_or((value, ""));
        let (cookie_name, cookie_value) = pair.split_once('=')?;
        (cookie_name.trim() == name).then(|| cookie_value.trim().to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head_with(headers: Vec<(&str, &str)>) -> Head {
        Head {
            status: 200,
            headers: headers
                .into_iter()
                .map(|(n, v)| (n.to_owned(), v.to_owned()))
                .collect(),
        }
    }

    #[test]
    fn the_named_cookie_is_picked_out_of_its_attributes() {
        let head = head_with(vec![(
            "Set-Cookie",
            "webvpn=deadbeef; Secure; HttpOnly; Path=/",
        )]);
        assert_eq!(cookie(&head, "webvpn").as_deref(), Some("deadbeef"));
    }

    #[test]
    fn an_unrelated_cookie_is_not_mistaken_for_it() {
        let head = head_with(vec![("Set-Cookie", "session=abc")]);
        assert_eq!(cookie(&head, "webvpn"), None);
    }

    #[test]
    fn several_set_cookie_headers_are_all_checked() {
        let head = head_with(vec![
            ("Set-Cookie", "session=abc"),
            ("Set-Cookie", "webvpn=xyz; Secure"),
        ]);
        assert_eq!(cookie(&head, "webvpn").as_deref(), Some("xyz"));
    }

    #[tokio::test]
    async fn a_body_shorter_than_content_length_is_a_disconnect() {
        let head = head_with(vec![("Content-Length", "10")]);
        let mut io = std::io::Cursor::new(b"short".to_vec());
        let err = read_body(&mut io, &head, Vec::new())
            .await
            .expect_err("короче");
        assert!(matches!(err, OpenConnectError::Disconnected(_)), "{err}");
    }

    #[tokio::test]
    async fn a_body_without_content_length_is_read_until_the_connection_closes() {
        let head = head_with(vec![]);
        let mut io = std::io::Cursor::new(b"<config-auth/>".to_vec());
        let body = read_body(&mut io, &head, Vec::new())
            .await
            .expect("читается");
        assert_eq!(body, b"<config-auth/>");
    }

    #[tokio::test]
    async fn bytes_that_arrived_with_the_head_count_toward_the_body() {
        let head = head_with(vec![("Content-Length", "4")]);
        let mut io = std::io::Cursor::new(b"ee".to_vec());
        let body = read_body(&mut io, &head, b"tw".to_vec())
            .await
            .expect("читается");
        assert_eq!(body, b"twee");
    }
}
