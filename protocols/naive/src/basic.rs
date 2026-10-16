//! Пароль в заголовке `Proxy-Authorization` (RFC 7617).
//!
//! `имя:пароль` в base64 ([`penguin_core::base64`]).

use penguin_core::base64;

/// Значение заголовка `Proxy-Authorization` целиком.
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
