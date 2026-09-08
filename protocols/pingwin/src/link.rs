//! Ссылка-приглашение: профиль одной строкой.
//!
//! ```text
//! pingwin://<пароль>@<хост>:<порт>?key=<ключ>&sni=<прикрытие>#<имя>
//! ```
//!
//! Запись та же, что у Trojan и Hysteria 2, и это не подражание: ссылку
//! пересылают в мессенджере, вставляют в клиент и там разбирают — чем меньше
//! она отличается от тех, что уже умеют вставлять, тем меньше шансов, что
//! половина строки потеряется по дороге.
//!
//! # Что здесь есть и чего нет
//!
//! Здесь только **сборка**. Разбор живёт в окне
//! (`penguin_gui::forms::protocol::pingwin`), и по-другому быть не может:
//! окно не вправе зависеть от крейта протокола (`AGENTS.md` §1). Заводить
//! здесь второй разбор, которым никто не пользуется, значило бы завести
//! второй ответ на вопрос, что делать с незнакомым параметром.
//!
//! Связывает две стороны образец: одна и та же строка стоит в тесте здесь и
//! в тесте окна. Разъедутся форматы — разъедутся и тесты.
//!
//! # Что попадает в ссылку
//!
//! Всё, без чего не подключиться, и ничего сверх: адрес, пароль, открытый
//! ключ сервера, имя прикрытия. Отпечаток браузера, шифр, 0-RTT и обход DPI
//! в ссылку не идут — у них рабочие умолчания, а обход к тому же подбирают
//! под сеть, в которой сидит клиент, а не под сервер, который выдал ссылку.

use crate::wire::keys::PUBLIC_LEN;

/// Схема ссылки. Стоит в чужих буферах обмена — менять нельзя.
pub const SCHEME: &str = "pingwin://";

/// Порт, который подразумевается, если в ссылке его нет.
pub const DEFAULT_PORT: u16 = 443;

/// Из чего собирается ссылка.
pub struct LinkParams<'a> {
    /// Хост, по которому клиент придёт. Может отличаться от того, что сервер
    /// слушает: за ним бывает проброс портов.
    pub host: &'a str,
    /// Порт, по которому клиент придёт.
    pub port: u16,
    /// Пароль пользователя.
    pub password: &'a str,
    /// Открытый ключ сервера.
    pub server_public: &'a [u8; PUBLIC_LEN],
    /// Имя прикрытия — то, что уйдёт в SNI.
    pub sni: &'a str,
    /// Имя профиля, которое увидит человек.
    pub name: &'a str,
}

/// Собирает ссылку-приглашение.
pub fn build(params: &LinkParams<'_>) -> String {
    // IPv6 в скобках: без них `2001:db8::1:443` — законный адрес сам по себе,
    // и где в нём порт, не знает никто.
    let host = if params.host.contains(':') && !params.host.starts_with('[') {
        format!("[{}]", params.host)
    } else {
        params.host.to_owned()
    };

    let mut link = String::from(SCHEME);
    link.push_str(&escape(params.password));
    link.push('@');
    link.push_str(&host);
    link.push(':');
    link.push_str(&params.port.to_string());

    // Ключ — алфавитом для URL и без дополнения: `+`, `/` и `=` в ссылке
    // пришлось бы экранировать, а половина клиентов этого не делает.
    link.push_str("?key=");
    link.push_str(&penguin_core::base64::encode_url(params.server_public));

    if !params.sni.is_empty() {
        link.push_str("&sni=");
        link.push_str(&escape(params.sni));
    }
    if !params.name.is_empty() {
        link.push('#');
        link.push_str(&escape(params.name));
    }
    link
}

/// Экранирует всё, что не буква, цифра и `-._~`.
///
/// Грубо и намеренно: список «безопасных» символов у userinfo, запроса и
/// имени после `#` разный, а неэкранированный `@` в пароле означает ссылку,
/// которая разбирается не туда. Лишний процент читается всеми одинаково,
/// недостающий — по-разному.
fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Образец, по которому сверяются обе стороны.
    ///
    /// Ровно эта строка стоит в тесте окна
    /// (`penguin_gui::forms::protocol::pingwin`). Правка формата ломает оба
    /// теста сразу — в этом и смысл.
    const SAMPLE: &str = "pingwin://s3cret@example.com:443\
?key=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\
&sni=www.microsoft.com#%D0%94%D0%BE%D0%BC%D0%B0";

    fn params<'a>(password: &'a str, name: &'a str) -> LinkParams<'a> {
        LinkParams {
            host: "example.com",
            port: 443,
            password,
            server_public: &[7u8; PUBLIC_LEN],
            sni: "www.microsoft.com",
            name,
        }
    }

    #[test]
    fn the_link_matches_the_sample_the_window_reads() {
        assert_eq!(build(&params("s3cret", "Дома")), SAMPLE);
    }

    #[test]
    fn the_key_carries_no_characters_a_url_would_eat() {
        // `+`, `/` и `=` в запросе разбираются по-разному: `+` у половины
        // клиентов означает пробел, и ключ приезжает не тем.
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
        // `@` внутри пароля означал бы ссылку, которая разбирается не туда:
        // всё до последней собаки — userinfo.
        let link = build(&params("p@ss:wo/rd#1", "имя"));
        assert!(link.contains("p%40ss%3Awo%2Frd%231"), "{link}");
        assert_eq!(link.matches('@').count(), 1, "лишняя собака: {link}");
        assert_eq!(link.matches('#').count(), 1, "лишняя решётка: {link}");
    }

    #[test]
    fn an_ipv6_host_keeps_its_brackets() {
        // Без скобок непонятно, где кончается адрес и начинается порт.
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
        // Схема стоит в чужих буферах обмена: сменить её — сломать все
        // разосланные ссылки разом.
        assert_eq!(SCHEME, "pingwin://");
        assert!(build(&params("s3cret", "имя")).starts_with(SCHEME));
    }
}
