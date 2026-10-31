//! TrustTunnel — описание формы.

use crate::forms::check;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Чем несётся `CONNECT`; HTTP/2 первым: проходит там, где UDP режут.
const TRANSPORTS: &[&str] = &["h2", "h3"];

/// Имя и пароль обязательны: уходят в `proxy-authorization` каждого запроса,
/// пустые дают `407`.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::text("username", &["username"], |s| s.username).required(|s| s.need_username),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    FieldSpec::choice("transport", &["transport"], |s| s.transport, TRANSPORTS),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
];

/// Описание протокола. Ссылок нет: своей записи `схема://` у протокола не сложилось.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "trusttunnel",
    label: "TrustTunnel",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_credentials_are_required_because_they_go_in_every_request() {
        for key in ["username", "password"] {
            let field = FIELDS
                .iter()
                .find(|field| field.key == key)
                .expect("поле есть");
            assert!(field.required.is_some(), "{key}");
        }
    }

    #[test]
    fn the_password_is_hidden_because_it_flies_in_every_request() {
        let password = FIELDS
            .iter()
            .find(|field| field.key == "password")
            .expect("поле есть");
        assert!(password.is_secret());
    }

    #[test]
    fn the_transports_match_the_ones_the_protocol_knows() {
        assert_eq!(TRANSPORTS, ["h2", "h3"]);
        assert!(FIELDS.iter().any(|field| field.key == "transport"));
    }
}
