//! MASQUE `CONNECT-IP` — описание формы.

use crate::forms::check;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Поля формы в том порядке, в каком они показываются.
///
/// Адреса интерфейса, MTU и маршрутов здесь нет: RFC 9484 отдаёт их
/// капсулами согласования уже после подключения (`ADDRESS_ASSIGN`), а не
/// настройкой профиля — та же история, что у OpenConnect, только другими
/// байтами на проводе. Опознания RFC 9484 тоже не описывает — как и у
/// `masque::SPEC`, поле `authorization` уходит заголовком как есть, и
/// обязательным его сделать нельзя.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::secret("authorization", &["authorization"], |s| s.authorization)
        .example(|s| s.optional_hint),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
];

/// Описание протокола.
///
/// Подпись называет режим отдельно от `masque::SPEC`: `CONNECT-IP` — другой
/// протокол по устройству (труба для пакетов, а не для датаграмм с адресом),
/// и общее имя «MASQUE» без уточнения обещало бы оба режима сразу.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "masque-ip",
    label: "MASQUE (CONNECT-IP)",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    // RFC 9484 не даёт способа назначить сервер имён внутри тоннеля.
    note: Some(|s| s.masque_ip_no_dns),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_says_out_loud_that_there_is_no_dns() {
        // Молчание здесь означало бы, что доменные имена через тоннель
        // никогда не работают, и человек искал бы причину в сети.
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
