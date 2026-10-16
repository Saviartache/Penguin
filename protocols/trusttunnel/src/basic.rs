//! Пароль в заголовке `proxy-authorization` (RFC 7617).
//!
//! `Basic base64(username:password)` на каждом `CONNECT`, включая псевдо-хосты
//! (`PROTOCOL.md`, §9.1, §6.2, §7.2, §8.2); кодировщик — [`penguin_core::base64`].

use penguin_core::base64;

/// Значение заголовка `proxy-authorization` целиком.
pub fn header_value(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64::encode(format!("{username}:{password}").as_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_classic_example_from_the_rfc() {
        assert_eq!(
            header_value("Aladdin", "open sesame"),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn a_password_with_non_ascii_survives() {
        let value = header_value("пользователь", "пароль");
        assert!(value.starts_with("Basic "));
        assert!(value.len() > "Basic ".len());
    }
}
