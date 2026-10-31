//! SOCKS5 — описание формы, в открытую и под TLS.
//!
//! Поля почти общие: у `socks5-tls` добавляются имя для TLS и отказ от проверки
//! сертификата. Переключатель UDP подписан по-разному: под TLS датаграммы в него
//! не заворачиваются (у `UDP ASSOCIATE` потока нет), и DNS уходит открыто.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали: на нём поднимается `ssh -D`.
const DEFAULT_PORT: u16 = 1080;

/// Поля прокси без TLS.
static PLAIN: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.proxy_address)
        .example(|s| s.socks_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::text("username", &["username"], |s| s.username).example(|s| s.optional_hint),
    FieldSpec::secret("password", &["password"], |s| s.password).example(|s| s.optional_hint),
    // Включён, как в протоколе: без UDP не уйдёт ни один DNS-запрос.
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Поля прокси под TLS: те же плюс сам TLS.
static SECURE: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.proxy_address)
        .example(|s| s.socks_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::text("username", &["username"], |s| s.username).example(|s| s.optional_hint),
    FieldSpec::secret("password", &["password"], |s| s.password).example(|s| s.optional_hint),
    // Подпись другая: сказать об открытом UDP надо там, где ставят флажок.
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp_plain).on(),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
];

/// Прокси без TLS. `socks5h` — разрешает прокси, а мы и так отдаём ему имя.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "socks5",
    label: "SOCKS5",
    fields: PLAIN,
    schemes: &["socks5://", "socks://", "socks5h://"],
    from_link: Some(from_link),
};

/// Прокси под TLS. Схемы ссылок нет: `socks5://` занята, договорённости о второй нет.
pub static TLS: ProtocolSpec = ProtocolSpec {
    id: "socks5-tls",
    label: "SOCKS5 over TLS",
    fields: SECURE,
    schemes: &[],
    from_link: None,
};

/// Как ссылка ложится в поля. Двоеточие в userinfo — разделитель (RFC 1929
/// передаёт имя и пароль раздельно), в отличие от Hysteria 2.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let mut values = vec![("server", link.server(DEFAULT_PORT))];

    let userinfo = link.userinfo();
    if !userinfo.is_empty() {
        // Бывает имя с пустым паролем.
        let (username, password) = userinfo.split_once(':').unwrap_or((&userinfo, ""));
        values.push(("username", username.to_owned()));
        values.push(("password", password.to_owned()));
    }

    Ok(values)
}
