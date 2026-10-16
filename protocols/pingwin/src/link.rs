//! Ссылка-приглашение: профиль одной строкой.
//!
//! ```text
//! pingwin://<пароль>@<хост>:<порт>?key=<ключ>&sni=<имя в сертификате>#<профиль>
//! ```
//!
//! Только сборка; разбор - в окне (`penguin_gui::forms::protocol::pingwin`, оно не
//! зависит от протокола, `AGENTS.md` §1). Общий образец стоит в тестах обоих.

use std::fmt::Write;

use crate::wire::keys::PUBLIC_LEN;

/// Схема ссылки (менять нельзя).
pub const SCHEME: &str = "pingwin://";

/// Порт, который подразумевается, если в ссылке его нет.
pub const DEFAULT_PORT: u16 = 443;

/// Из чего собирается ссылка.
pub struct LinkParams<'a> {
    /// Хост, по которому клиент придёт.
    pub host: &'a str,
    /// Порт, по которому клиент придёт.
    pub port: u16,
    /// Пароль пользователя.
    pub password: &'a str,
    /// Открытый ключ сервера.
    pub server_public: &'a [u8; PUBLIC_LEN],
    /// Имя в сертификате сервера. Пусто — то же, что хост.
    pub sni: &'a str,
    /// Имя профиля, которое увидит человек.
    pub name: &'a str,
}

/// Собирает ссылку-приглашение.
pub fn build(params: &LinkParams<'_>) -> String {
    let host = if params.host.contains(':') && !params.host.starts_with('[') {
        format!("[{}]", params.host)
    } else {
        params.host.to_owned()
    };

    let mut link = String::from(SCHEME);
    link.push_str(&escape(params.password));
    link.push('@');
    link.push_str(&host);
    let _ = write!(link, ":{}", params.port);

    link.push_str("?key=");
    link.push_str(&penguin_core::base64::encode_url(params.server_public));

    if !params.sni.is_empty() && params.sni != params.host {
        link.push_str("&sni=");
        link.push_str(&escape(params.sni));
    }
    if !params.name.is_empty() {
        link.push('#');
        link.push_str(&escape(params.name));
    }
    link
}

/// Экранирует всё, кроме букв, цифр и `-._~` (лишний процент читается всеми одинаково).
fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(*byte as char);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Та же строка стоит в тесте окна.
    const SAMPLE: &str = "pingwin://s3cret@203.0.113.5:443\
?key=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\
&sni=vpn.example.com#%D0%94%D0%BE%D0%BC%D0%B0";

    fn params<'a>(password: &'a str, name: &'a str) -> LinkParams<'a> {
        LinkParams {
            host: "203.0.113.5",
            port: 443,
            password,
            server_public: &[7u8; PUBLIC_LEN],
            sni: "vpn.example.com",
            name,
        }
    }

    #[test]
    fn a_name_equal_to_the_host_is_not_repeated() {
        let link = build(&LinkParams {
            host: "vpn.example.com",
            ..params("s3cret", "")
        });
        assert!(!link.contains("sni="), "{link}");
    }

    #[test]
    fn the_link_matches_the_sample_the_window_reads() {
        assert_eq!(build(&params("s3cret", "Дома")), SAMPLE);
    }

    #[test]
    fn the_key_carries_no_characters_a_url_would_eat() {
        let link = build(&params("s3cret", "Дома"));
        let key = link
            .split_once("?key=")
            .and_then(|(_, rest)| rest.split('&').next())
            .expect("ключ в ссылке есть");
        assert!(
            !key.contains(['+', '/', '=']),
            "ключ придётся экранировать: {key}"
        );
    }

    #[test]
    fn a_password_with_reserved_characters_survives() {
        let link = build(&params("p@ss:wo/rd#1", "имя"));
        assert!(link.contains("p%40ss%3Awo%2Frd%231"), "{link}");
        assert_eq!(link.matches('@').count(), 1, "лишняя собака: {link}");
        assert_eq!(link.matches('#').count(), 1, "лишняя решётка: {link}");
    }

    #[test]
    fn an_ipv6_host_keeps_its_brackets() {
        let link = build(&LinkParams {
            host: "2001:db8::1",
            ..params("s3cret", "имя")
        });
        assert!(link.contains("[2001:db8::1]:443"), "{link}");
    }

    #[test]
    fn an_empty_name_leaves_no_dangling_hash() {
        let link = build(&params("s3cret", ""));
        assert!(!link.contains('#'), "{link}");
    }

    #[test]
    fn the_scheme_is_stable() {
        assert_eq!(SCHEME, "pingwin://");
        assert!(build(&params("s3cret", "имя")).starts_with(SCHEME));
    }
}
