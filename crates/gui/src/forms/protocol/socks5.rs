//! SOCKS5 — описание формы.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
///
/// 1080 — обычай, а не правило, но именно на нём поднимается `ssh -D` и любой
/// локальный прокси по умолчанию.
const DEFAULT_PORT: u16 = 1080;

/// Поля формы в том порядке, в каком они показываются.
static FIELDS: &[FieldSpec] = &[
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

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "socks5",
    label: "SOCKS5",
    fields: FIELDS,
    // `socks5h` отличается от `socks5` тем, что имя разрешает прокси, — а мы
    // и так всегда отдаём имя прокси, иначе правила по доменам теряют смысл.
    schemes: &["socks5://", "socks://", "socks5h://"],
    from_link: Some(from_link),
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
