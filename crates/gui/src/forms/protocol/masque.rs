//! MASQUE — описание формы.

use crate::forms::check;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Опознания в RFC 9298 нет: `authorization` уходит заголовком как есть и не
/// обязателен (прокси без опознания законен). Общие поля с `CONNECT-IP`.
pub(super) static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::secret("authorization", &["authorization"], |s| s.authorization)
        .example(|s| s.optional_hint),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
];

/// Описание протокола; подпись называет режим, `CONNECT-IP` не сделан.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "masque",
    label: "MASQUE (CONNECT-UDP)",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    // TCP через это направление не ходит.
    note: Some(|s| s.masque_udp_only),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_says_out_loud_that_there_is_no_tcp() {
        assert!(SPEC.note.is_some());
    }

    #[test]
    fn authorization_is_optional_because_the_rfc_has_no_authentication() {
        let field = FIELDS
            .iter()
            .find(|field| field.key == "authorization")
            .expect("поле есть");
        assert!(field.required.is_none());
        assert!(field.is_secret(), "учётные данные показаны открытыми");
    }

    #[test]
    fn there_is_no_udp_switch_because_udp_is_all_there_is() {
        assert!(FIELDS.iter().all(|field| field.key != "udp"));
    }
}
