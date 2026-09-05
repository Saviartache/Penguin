//! Snell — описание формы.

use crate::forms::check;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Версии протокола.
///
/// Порядок — это порядок в списке, и первое значение становится значением
/// нового профиля. Сверху четвёртая: её и пятую говорят нынешние серверы, а
/// первые три остались у старых.
///
/// Умолчания у версии в настройках нет: профиль, в котором её не написали,
/// протокол отвергает. Здесь же выбрать что-то надо — поле выбора пустым не
/// бывает, — и выбрано то, что чаще всего верно.
const VERSIONS: &[&str] = &["4", "5", "3", "2", "1"];

/// Чем прикрыто соединение.
///
/// Первое — «ничем»: так стоит у большинства серверов, и обфускация, которую
/// сервер не ждёт, даёт молчащее соединение так же надёжно, как её отсутствие
/// там, где ждут.
const OBFS: &[&str] = &["none", "http", "tls"];

/// Поля формы в том порядке, в каком они показываются.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::secret("psk", &["psk"], |s| s.psk).required(|s| s.need_psk),
    // Список, а не строка: версии несовместимы, а неверная не даёт отказа —
    // сервер расшифровывает первый кусок другим шифром и молчит.
    FieldSpec::choice("version", &["version"], |s| s.snell_version, VERSIONS),
    FieldSpec::choice("obfs", &["obfs"], |s| s.obfs, OBFS),
    FieldSpec::text("obfs_host", &["obfs_host"], |s| s.obfs_host).example(|s| s.obfs_host_example),
    // Датаграммы появились с третьей версии; у первых двух этот флаг ничего
    // не включит, и направление честно скажет, что UDP не умеет.
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Описание протокола.
///
/// Ссылок нет: своей записи для обмена профилями у Snell не сложилось. Surge
/// хранит их в собственном файле настроек, остальные клиенты — в YAML.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "snell",
    label: "Snell",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    note: None,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_newest_version_is_the_one_a_new_profile_gets() {
        // Первые три остались у старых серверов; нынешние говорят четвёртой.
        assert_eq!(VERSIONS.first(), Some(&"4"));
    }

    #[test]
    fn every_version_of_the_protocol_is_in_the_list() {
        let mut numbers: Vec<u8> = VERSIONS
            .iter()
            .map(|version| version.parse().expect("число"))
            .collect();
        numbers.sort_unstable();
        assert_eq!(numbers, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn no_obfuscation_is_the_one_a_new_profile_gets() {
        // Обфускация, которой сервер не ждёт, даёт молчащее соединение.
        assert_eq!(OBFS.first(), Some(&"none"));
    }

    #[test]
    fn the_label_of_the_version_says_that_there_is_no_specification() {
        // Протокол закрыт, описания не публиковали; человек, выбирающий
        // версию наугад, должен знать, откуда взялся этот список.
        let label = (FIELDS[2].label)(crate::i18n::s());
        assert!(label.contains("описание"), "{label}");
    }
}
