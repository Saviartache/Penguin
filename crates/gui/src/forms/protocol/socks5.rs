//! SOCKS5 — описание формы, в открытую и под TLS.
//!
//! Описаний два, а полей почти одни и те же: у `socks5-tls` к ним добавляются
//! имя для TLS и отказ от проверки сертификата. Разделены они там же, где и в
//! самом протоколе, и по той же причине: через `socks5` адрес назначения и
//! пароль уходят по сети читаемыми, через `socks5-tls` — внутри TLS.
//!
//! Одно поле у них всё же разное — переключатель UDP. Под TLS датаграммы в
//! него не заворачиваются: TLS живёт поверх потока, а у `UDP ASSOCIATE`
//! потока нет. Подпись это и говорит, потому что иначе человек будет считать
//! защищённым каждый свой запрос DNS.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
///
/// 1080 — обычай, а не правило, но именно на нём поднимается `ssh -D` и любой
/// локальный прокси по умолчанию.
const DEFAULT_PORT: u16 = 1080;

/// Поля прокси без TLS, в том порядке, в каком они показываются.
static PLAIN: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.proxy_address)
        .example(|s| s.socks_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::text("username", &["username"], |s| s.username).example(|s| s.optional_hint),
    FieldSpec::secret("password", &["password"], |s| s.password).example(|s| s.optional_hint),
    // Включён по умолчанию — как и в самом протоколе: без UDP в направление
    // не уйдёт ни один DNS-запрос. Выключают его те, чей прокси не умеет
    // `UDP ASSOCIATE`.
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
    // Подпись другая, чем у `socks5`: под TLS датаграммы уходят мимо него, и
    // сказать об этом надо там, где человек ставит флажок, а не в документации.
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp_plain).on(),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
];

/// Прокси без TLS.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "socks5",
    label: "SOCKS5",
    fields: PLAIN,
    // `socks5h` отличается от `socks5` тем, что имя разрешает прокси, — а мы
    // и так всегда отдаём имя прокси, иначе правила по доменам теряют смысл.
    schemes: &["socks5://", "socks://", "socks5h://"],
    from_link: Some(from_link),
};

/// Прокси под TLS.
///
/// Своей схемы ссылок у него нет: `socks5://` занята обычным SOCKS5, а
/// договорённости о второй не существует — под TLS такой прокси поднимают
/// сами, и ссылку на него никто не рассылает.
pub static TLS: ProtocolSpec = ProtocolSpec {
    id: "socks5-tls",
    label: "SOCKS5 over TLS",
    fields: SECURE,
    schemes: &[],
    from_link: None,
};

/// Как ссылка ложится в поля.
///
/// В отличие от Hysteria 2, двоеточие в userinfo — **разделитель**: в RFC 1929
/// имя и пароль передаются двумя отдельными полями, и склеить их обратно
/// нельзя ни на какой стороне.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let mut values = vec![("server", link.server(DEFAULT_PORT))];

    let userinfo = link.userinfo();
    if !userinfo.is_empty() {
        let (username, password) = match userinfo.split_once(':') {
            Some((username, password)) => (username, password),
            // Прокси, спрашивающий имя и пустой пароль, встречается.
            None => (userinfo.as_str(), ""),
        };
        values.push(("username", username.to_owned()));
        values.push(("password", password.to_owned()));
    }

    Ok(values)
}
