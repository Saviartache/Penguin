//! Relay из GOST — описание формы.

use crate::forms::check;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Чем шифруется соединение до сервера.
///
/// Первое — умолчание нового профиля, и это «ничем». Своего шифрования у
/// протокола нет вовсе: без TLS снизу и пароль, и адрес назначения идут
/// открытым текстом. Ставить сюда `tls` по умолчанию нельзя — сервер, который
/// его не ждёт, просто не ответит; но сказать об этом человеку обязаны.
const SECURITY: &[&str] = &["none", "tls"];

/// Чем переносится поток.
const TRANSPORTS: &[&str] = &["tcp", "ws", "httpupgrade"];

/// Поля формы в том порядке, в каком они показываются.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    // Ни имя, ни пароль не обязательны: сервер без настроенных пользователей
    // не спрашивает их вовсе, и требовать их значило бы не пускать к нему.
    FieldSpec::text("username", &["username"], |s| s.username).example(|s| s.optional_hint),
    FieldSpec::secret("password", &["password"], |s| s.password).example(|s| s.optional_hint),
    FieldSpec::choice("security", &["security"], |s| s.security, SECURITY),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
    FieldSpec::choice("transport", &["transport"], |s| s.transport, TRANSPORTS),
    FieldSpec::text("path", &["path"], |s| s.path).example(|s| s.path_example),
    FieldSpec::text("host", &["host"], |s| s.http_host).example(|s| s.optional_hint),
    // UDP здесь — не общий канал, а поток на каждого адресата: настоящего
    // `UDP ASSOCIATE` сервер по умолчанию не включает.
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Описание протокола.
///
/// Ссылок нет: своей записи для обмена профилями у этого протокола не
/// сложилось — в `gost` профиль задают строкой запуска, а не ссылкой.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "gost-relay",
    label: "GOST Relay",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    note: None,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_profile_gets_no_encryption_because_the_server_expects_none() {
        // Сервер, который не ждёт TLS, на приветствие не ответит. Умолчание
        // обязано совпадать с умолчанием сервера, а не с тем, что безопаснее.
        assert_eq!(SECURITY.first(), Some(&"none"));
        assert_eq!(TRANSPORTS.first(), Some(&"tcp"));
    }

    #[test]
    fn neither_the_name_nor_the_password_is_required() {
        // Сервер без настроенных пользователей не спрашивает их вовсе;
        // требовать их значило бы не пускать к такому серверу.
        for key in ["username", "password"] {
            let field = FIELDS
                .iter()
                .find(|field| field.key == key)
                .expect("поле есть");
            assert!(field.required.is_none(), "{key}");
        }
    }
}
