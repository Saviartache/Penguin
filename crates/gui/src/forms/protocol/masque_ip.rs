//! MASQUE `CONNECT-IP` — описание формы.

use crate::forms::protocol::masque::FIELDS;
use crate::forms::protocol::spec::ProtocolSpec;

/// Описание протокола. Поля общие с `masque`; адреса, MTU и маршрутов нет: RFC 9484
/// отдаёт их капсулами после подключения. Подпись называет режим: имя «MASQUE»
/// обещало бы оба.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "masque-ip",
    label: "MASQUE (CONNECT-IP)",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    // RFC 9484 не назначает DNS внутри тоннеля.
    note: Some(|s| s.masque_ip_no_dns),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_says_out_loud_that_there_is_no_dns() {
        assert!(SPEC.note.is_some());
    }

    #[test]
    fn nothing_the_server_hands_out_is_asked_of_the_person() {
        for key in ["address_ipv4", "address_ipv6", "mtu", "routes", "dns"] {
            assert!(
                FIELDS.iter().all(|field| field.key != key),
                "поле `{key}` спрашивает то, что скажет сервер"
            );
        }
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
}
