//! OpenConnect — описание формы.

use crate::forms::check;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Поля формы в том порядке, в каком они показываются.
///
/// Ни адреса интерфейса, ни MTU, ни маршрутов здесь нет, в отличие от
/// WireGuard: у этого протокола их сообщает **сервер** при входе. Спрашивать
/// их у человека значило бы спрашивать то, чего он знать не обязан, — и
/// получить ответ, который всё равно будет заменён.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::text("username", &["username"], |s| s.username).required(|s| s.need_username),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    // Группа есть не у всех серверов, и по умолчанию берётся та, что сервер
    // предлагает сам.
    FieldSpec::text("group", &["group"], |s| s.login_group).example(|s| s.optional_hint),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "openconnect",
    label: "OpenConnect",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    // DTLS нет, и это видно на скорости, а не в ошибке: человек решит, что
    // виноват сервер или сеть.
    note: Some(|s| s.openconnect_no_dtls),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_says_out_loud_that_there_is_no_dtls() {
        // Весь трафик идёт по TCP внутри TLS, то есть TCP поверх TCP со всеми
        // его бедами. Молчание тут выглядело бы медленным сервером.
        assert!(SPEC.note.is_some());
    }

    #[test]
    fn nothing_the_server_hands_out_is_asked_of_the_person() {
        // Адрес интерфейса, MTU, маршруты и DNS приходят при входе. Поле для
        // них означало бы вопрос, ответ на который всё равно будет заменён.
        for key in ["address_ipv4", "mtu", "routes", "dns"] {
            assert!(
                FIELDS.iter().all(|field| field.key != key),
                "поле `{key}` спрашивает то, что скажет сервер"
            );
        }
    }

    #[test]
    fn the_group_is_optional_because_the_server_offers_a_default() {
        let field = FIELDS
            .iter()
            .find(|field| field.key == "group")
            .expect("поле есть");
        assert!(field.required.is_none());
    }
}
