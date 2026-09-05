//! NaiveProxy — описание формы. Две записи: по HTTP/2 и по HTTP/3.

use crate::forms::check;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Поля формы в том порядке, в каком они показываются.
///
/// Флага TLS здесь нет, в отличие от `http`/`https`: смысл протокола в том,
/// что снаружи соединение неотличимо от обычного HTTPS до веб-сайта, и
/// разговор в открытую снял бы маскировку целиком. TLS тут всегда.
///
/// Имя и пароль необязательны: сервер без учётных данных бывает — редко, но
/// бывает, — и требовать их значило бы не пускать к нему.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::text("username", &["username"], |s| s.username).example(|s| s.optional_hint),
    FieldSpec::secret("password", &["password"], |s| s.password).example(|s| s.optional_hint),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
];

/// `CONNECT` поверх HTTP/2.
pub static HTTP2: ProtocolSpec = ProtocolSpec {
    id: "http2",
    label: "NaiveProxy (HTTP/2)",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    note: None,
};

/// `CONNECT` поверх HTTP/3.
///
/// Тот же протокол и тот же крейт, другой перенос: под HTTP/3 лежит QUIC, и
/// сеть с потерями он переживает лучше. Отдельной записью, а не полем выбора,
/// потому что сервер слушает их на разных портах и настраивает по-разному.
pub static HTTP3: ProtocolSpec = ProtocolSpec {
    id: "http3",
    label: "NaiveProxy (HTTP/3)",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    note: None,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn there_is_no_tls_switch_because_tls_is_the_whole_point() {
        // Разговор в открытую снял бы маскировку целиком, ради которой
        // протокол и придуман.
        assert!(FIELDS.iter().all(|field| field.key != "tls"));
    }

    #[test]
    fn neither_the_name_nor_the_password_is_required() {
        // Сервер без учётных данных бывает, и требовать их значило бы не
        // пускать к нему.
        for key in ["username", "password"] {
            let field = FIELDS
                .iter()
                .find(|field| field.key == key)
                .expect("поле есть");
            assert!(field.required.is_none(), "{key}");
        }
    }

    #[test]
    fn both_transports_ask_for_the_same_things() {
        // Протокол один, различие только в переносе: разойдись формы полями —
        // профиль, переписанный с одной на другую, потерял бы настройки.
        assert_eq!(HTTP2.fields.len(), HTTP3.fields.len());
        assert_ne!(HTTP2.id, HTTP3.id);
    }

    #[test]
    fn there_is_no_udp_switch_because_there_is_no_udp() {
        // У `CONNECT` датаграмм нет ни поверх HTTP/2, ни поверх HTTP/3.
        assert!(FIELDS.iter().all(|field| field.key != "udp"));
    }
}
