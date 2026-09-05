//! Brook — описание формы.

use crate::forms::check;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Чем переносится поток.
///
/// Первое — умолчание нового профиля. `direct` сверху не только потому, что
/// он проще: датаграммы есть **только** у него. У `ws` и `wss` их нет вовсе,
/// и переключение переноса молча выключает UDP.
const TRANSPORTS: &[&str] = &["direct", "ws", "wss"];

/// Поля формы в том порядке, в каком они показываются.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    FieldSpec::choice("transport", &["transport"], |s| s.transport, TRANSPORTS),
    FieldSpec::text("path", &["path"], |s| s.path).example(|s| s.path_example),
    FieldSpec::text("host", &["host"], |s| s.http_host).example(|s| s.optional_hint),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
    // Датаграммы есть только у `direct`: при `ws` и `wss` этот флаг ничего не
    // включит, и направление честно скажет, что UDP не умеет.
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Описание протокола.
///
/// Ссылок нет: у Brook своя запись профиля есть, но она не похожа на прочие —
/// это не `схема://`, а отдельный формат, и разбор её здесь пока не написан.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "brook",
    label: "Brook",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_only_transport_with_datagrams_is_the_default_one() {
        // У `ws` и `wss` датаграмм нет вовсе, и человек, переключивший
        // перенос, теряет UDP молча, если умолчание не такое.
        assert_eq!(TRANSPORTS.first(), Some(&"direct"));
    }

    #[test]
    fn the_password_is_required_because_the_key_comes_from_it() {
        let password = FIELDS
            .iter()
            .find(|field| field.key == "password")
            .expect("поле есть");
        assert!(password.required.is_some());
        assert!(password.is_secret(), "пароль показан открытым");
    }
}
