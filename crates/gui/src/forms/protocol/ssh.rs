//! SSH — описание формы.

use crate::forms::check;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Поля формы в том порядке, в каком они показываются.
///
/// Приватного ключа здесь нет, хотя протокол его умеет: ключ — это несколько
/// строк PEM, а поле формы однострочное, и вставленный в него ключ потеряет
/// переносы молча. Опознание ключом задаётся правкой файла настроек:
/// `private_key` и, если ключ зашифрован, `private_key_passphrase`.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::text("username", &["username"], |s| s.username).required(|s| s.need_username),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    // Обязателен: SSH без проверки хоста — это тот же `insecure`, только
    // молчаливый. Подпись говорит об этом прямо, а не прячет за примечанием.
    FieldSpec::text("host_fingerprint", &["host_fingerprint"], |s| {
        s.host_fingerprint
    })
    .example(|s| s.host_fingerprint_example)
    .required(|s| s.need_host_fingerprint),
];

/// Описание протокола.
///
/// Ссылок нет: `ssh://` в природе занят самим терминалом, и профиль клиента в
/// нём не выразить — отпечатка хоста в такой ссылке нет.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "ssh",
    label: "SSH",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    note: None,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_key_is_required() {
        // Без него любой перехвативший соединение становится сервером, и
        // клиент об этом не скажет ни слова.
        let field = FIELDS
            .iter()
            .find(|field| field.key == "host_fingerprint")
            .expect("поле есть");
        assert!(field.required.is_some());
        // Не секрет: публичный ключ сервера прячут разве что по ошибке, а
        // спрятанное поле нельзя сверить глазами с тем, что выдал сервер.
        assert!(!field.is_secret());
    }

    #[test]
    fn there_is_no_private_key_field_because_it_would_not_fit() {
        // Многострочный PEM в однострочном поле теряет переносы молча.
        assert!(FIELDS.iter().all(|field| field.key != "private_key"));
    }

    #[test]
    fn there_is_no_udp_switch_because_there_is_no_udp() {
        // `direct-tcpip` — это только TCP.
        assert!(FIELDS.iter().all(|field| field.key != "udp"));
    }
}
