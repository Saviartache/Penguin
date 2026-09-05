//! Пароль в заголовке `proxy-authorization` (RFC 7617).
//!
//! TrustTunnel не придумывает своей схемы опознания: `PROTOCOL.md`, §9.1,
//! требует ровно `Basic base64(username:password)` на **каждом** `CONNECT`
//! — включая псевдо-хосты `_udp2`, `_icmp` и `_check` (§6.2, §7.2, §8.2).
//!
//! Кодировщик не свой: он уже есть в [`penguin_core::base64`].

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
        // `Aladdin:open sesame` из RFC 7617.
        assert_eq!(
            header_value("Aladdin", "open sesame"),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn a_password_with_non_ascii_survives() {
        // Пароль на русском встречается; кодируется он байтами UTF-8, а не
        // знаками, и обрезать его нельзя.
        let value = header_value("пользователь", "пароль");
        assert!(value.starts_with("Basic "));
        assert!(value.len() > "Basic ".len());
    }
}
