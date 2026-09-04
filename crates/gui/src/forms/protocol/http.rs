//! Прокси HTTP CONNECT — описание формы, в открытую и под TLS.
//!
//! Описаний два, а полей почти одни и те же: у `https` к ним добавляются имя
//! для TLS и отказ от проверки сертификата. Разделены они там же, где и в
//! самом протоколе, и по той же причине: через `http` пароль уходит по сети
//! читаемым, через `https` — внутри TLS, и выбирают это в тот момент, когда
//! добавляют сервер, а не когда открывают файл настроек.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Поля прокси без TLS.
static PLAIN: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.proxy_address)
        .example(|s| s.http_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::text("username", &["username"], |s| s.username).example(|s| s.optional_hint),
    FieldSpec::secret("password", &["password"], |s| s.password).example(|s| s.optional_hint),
];

/// Поля прокси под TLS: те же плюс сам TLS.
static SECURE: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.proxy_address)
        .example(|s| s.https_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::text("username", &["username"], |s| s.username).example(|s| s.optional_hint),
    FieldSpec::secret("password", &["password"], |s| s.password).example(|s| s.optional_hint),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
];

/// Прокси без TLS.
pub static HTTP: ProtocolSpec = ProtocolSpec {
    id: "http",
    label: "HTTP",
    fields: PLAIN,
    schemes: &["http://"],
    from_link: Some(from_link),
};

/// Прокси под TLS.
pub static HTTPS: ProtocolSpec = ProtocolSpec {
    id: "https",
    label: "HTTPS",
    fields: SECURE,
    schemes: &["https://"],
    from_link: Some(from_link),
};

/// Как ссылка ложится в поля.
///
/// # Почему порт обязателен
///
/// Схемы `http://` и `https://` — это ещё и любая ссылка на страницу, и
/// вставляют их в поле ссылки чаще по ошибке, чем нарочно. Отличить одно от
/// другого можно ровно одним признаком: у прокси порт написан почти всегда, у
/// страницы — почти никогда. Поэтому ссылка без порта здесь отвергается с
/// объяснением, а не превращается молча в профиль «example.com:443», который
/// потом не подключается.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    if link.port.is_none() {
        return Err(crate::i18n::s().link_no_port.to_owned());
    }

    // Порт задан, и умолчание сюда не попадает; ноль стоит как заведомо
    // неиспользуемое значение.
    let mut values = vec![("server", link.server(0))];

    let userinfo = link.userinfo();
    if !userinfo.is_empty() {
        let (username, password) = match userinfo.split_once(':') {
            Some((username, password)) => (username, password),
            None => (userinfo.as_str(), ""),
        };
        values.push(("username", username.to_owned()));
        values.push(("password", password.to_owned()));
    }

    Ok(values)
}
