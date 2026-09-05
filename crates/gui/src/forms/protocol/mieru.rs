//! Mieru — описание формы.

use crate::forms::check;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Поля формы в том порядке, в каком они показываются.
///
/// Переключателя UDP здесь нет, и это не пропуск: датаграмм у протокола в
/// нашей реализации нет вовсе, и направление говорит об этом честно. Флаг,
/// который ничего не включает, хуже отсутствующего — человек ставит его и
/// ждёт, что запросы DNS пойдут в тоннель.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    // Имя участвует в выводе ключа наравне с паролем: без него ключ выйдет
    // другим, и сервер просто промолчит.
    FieldSpec::text("username", &["username"], |s| s.username).required(|s| s.need_username),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "mieru",
    label: "Mieru",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    note: None,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_is_required_because_the_key_comes_from_it_too() {
        // Оно участвует в выводе ключа наравне с паролем: пустое имя даёт
        // другой ключ и молчащий сервер, а не понятный отказ.
        let username = FIELDS
            .iter()
            .find(|field| field.key == "username")
            .expect("поле есть");
        assert!(username.required.is_some());
    }

    #[test]
    fn there_is_no_udp_switch_because_there_is_no_udp() {
        // Флаг, который ничего не включает, хуже отсутствующего.
        assert!(FIELDS.iter().all(|field| field.key != "udp"));
    }
}
