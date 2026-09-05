//! TrustTunnel — описание формы.

use crate::forms::check;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Поля формы в том порядке, в каком они показываются.
///
/// Выбора переноса нет: сделана только нога по HTTP/2. Спецификация прямо
/// говорит, что клиент **может** поддержать оба и что HTTP/2 достаточно, —
/// так что поле выбора обещало бы то, чего пока нет.
///
/// Имя и пароль обязательны: они уходят заголовком `proxy-authorization` в
/// каждом запросе, и пустые означают отказ `407` на первом же соединении.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::text("username", &["username"], |s| s.username).required(|s| s.need_username),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
];

/// Описание протокола.
///
/// Ссылок нет: своей записи `схема://` у протокола не сложилось — профиль
/// задаётся файлом настроек.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "trusttunnel",
    label: "TrustTunnel",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    note: None,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_credentials_are_required_because_they_go_in_every_request() {
        // Пустые означают `407` на первом же соединении, а не «сервер без
        // пароля»: у этого протокола пароль обязателен по спецификации.
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
    fn there_is_no_transport_choice_while_only_http2_is_done() {
        // Поле выбора обещало бы HTTP/3, которого пока нет.
        assert!(FIELDS.iter().all(|field| field.key != "transport"));
    }
}
