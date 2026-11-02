//! Запрос `CONNECT` и разбор ответа на него — без сети.

use crate::error::{I2pError, I2pResult};

/// Предел заголовка ответа: дальше — не прокси.
pub const HEAD_LIMIT: usize = 8 * 1024;

/// Конец заголовка HTTP/1.
pub const HEAD_END: &[u8] = b"\r\n\r\n";

/// Запрос `CONNECT` к `authority` (`хост:порт`, IPv6 в скобках).
pub fn connect_request(authority: &str) -> Vec<u8> {
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").into_bytes()
}

/// Код ответа из заголовка `HTTP/1.x NNN …`.
pub fn status_code(head: &[u8]) -> I2pResult<u16> {
    let line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut words = line.split_ascii_whitespace();
    let malformed = || I2pError::Malformed(line.chars().take(64).collect());

    let version = words.next().ok_or_else(malformed)?;
    if !version.starts_with("HTTP/1.") {
        return Err(malformed());
    }
    words
        .next()
        .filter(|code| code.len() == 3)
        .and_then(|code| code.parse().ok())
        .ok_or_else(malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `HTTPRes::to_string` i2pd 3.0.0 после потока до `.b32.i2p` (`HandleHTTPConnectStreamRequestComplete`).
    const I2PD_OK: &[u8] = b"HTTP/1.1 200 OK\r\nDate: Mon, 02 Nov 2026 10:00:00 GMT\r\n\r\n";

    // `GenericProxyError(…, HTTP_CODE_BAD_GATEWAY)` i2pd 3.0.0: поток не открылся.
    const I2PD_FAILED: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: 80\r\nDate: Mon, 02 Nov 2026 10:00:00 GMT\r\n\r\n";

    #[test]
    fn the_request_names_the_authority_twice() {
        assert_eq!(
            connect_request("example.com:443"),
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        );
    }

    #[test]
    fn i2pd_replies_are_read() {
        assert_eq!(status_code(I2PD_OK).expect("200"), 200);
        assert_eq!(status_code(I2PD_FAILED).expect("502"), 502);
    }

    // Ответ outproxy не записан: живой не проверялся, строка — по RFC 9110 §9.3.6.
    #[test]
    fn an_outproxy_reason_phrase_does_not_matter() {
        assert_eq!(
            status_code(b"HTTP/1.0 200 Connection established\r\n\r\n").expect("200"),
            200
        );
    }

    #[test]
    fn not_http_is_malformed() {
        for head in [
            &b"SSH-2.0-OpenSSH_9.6\r\n"[..],
            b"\x05\x00",
            b"HTTP/2 200\r\n\r\n",
            b"HTTP/1.1 OK\r\n",
        ] {
            assert!(matches!(status_code(head), Err(I2pError::Malformed(_))));
        }
    }
}
