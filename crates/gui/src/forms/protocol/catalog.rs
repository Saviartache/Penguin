//! Все протоколы, какие окно умеет показать.
//!
//! Порядок здесь — это порядок в списке выбора, и он не алфавитный. Сверху то,
//! ради чего клиент и ставят: Hysteria 2 — единственный из четырёх, который
//! придуман, чтобы работать в плохой сети и не выглядеть собой. Прокси ниже:
//! они проще, честнее и уместны там, где сеть своя.

use crate::forms::protocol::spec::ProtocolSpec;
use crate::forms::protocol::{http, hysteria2, socks5, trojan};

/// Протоколы в порядке показа.
///
/// Добавление протокола — строка здесь и файл с описанием рядом. Ни экран
/// выбора, ни редактор, ни разбор ссылок при этом не трогаются.
pub static ALL: &[&ProtocolSpec] = &[
    &hysteria2::SPEC,
    &trojan::SPEC,
    &socks5::TLS,
    &socks5::SPEC,
    &http::HTTPS,
    &http::HTTP,
];

/// Чем заполняется форма, когда протокол не выбирали.
///
/// Такое бывает ровно в одном месте — в тестах и в пустом состоянии окна:
/// человек до формы иначе как через выбор протокола не доходит.
pub static DEFAULT: &ProtocolSpec = &hysteria2::SPEC;

/// Описание по имени протокола из настроек.
///
/// `None` — протокол в этой сборке окна неизвестен. Это не поломка: файл
/// настроек мог прийти от новой версии, и профиль в нём надо показать, а не
/// потерять (см. [`crate::forms::server::Draft`]).
pub fn by_id(id: &str) -> Option<&'static ProtocolSpec> {
    ALL.iter().copied().find(|spec| spec.id == id)
}

/// Описание по схеме ссылки: `hy2`, `socks5`.
///
/// Схема приходит без `://` — так её отдаёт [`crate::forms::link::split`].
pub fn by_scheme(scheme: &str) -> Option<&'static ProtocolSpec> {
    let scheme = scheme.trim().to_lowercase();
    ALL.iter().copied().find(|spec| {
        spec.schemes
            .iter()
            .any(|known| known.trim_end_matches("://") == scheme)
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn every_protocol_is_findable_by_its_name() {
        for spec in ALL {
            assert_eq!(
                by_id(spec.id).map(|found| found.id),
                Some(spec.id),
                "`{}` не находится по имени",
                spec.id
            );
        }
        assert!(by_id("телепатия").is_none());
    }

    #[test]
    fn names_and_labels_are_unique() {
        // Два описания с одним именем означают, что профиль откроется не тем
        // протоколом, каким сохранён.
        let ids: HashSet<&str> = ALL.iter().map(|spec| spec.id).collect();
        assert_eq!(ids.len(), ALL.len(), "повторяется имя протокола");

        let labels: HashSet<&str> = ALL.iter().map(|spec| spec.label).collect();
        assert_eq!(labels.len(), ALL.len(), "повторяется подпись протокола");
    }

    #[test]
    fn schemes_belong_to_one_protocol_each() {
        // Иначе ссылка разбиралась бы то одним протоколом, то другим — в
        // зависимости от порядка в списке.
        let mut seen = HashSet::new();
        for spec in ALL {
            for scheme in spec.schemes {
                assert!(seen.insert(*scheme), "схема `{scheme}` занята дважды");
                assert!(scheme.ends_with("://"), "схема `{scheme}` без `://`");
                assert_eq!(
                    by_scheme(scheme.trim_end_matches("://")).map(|found| found.id),
                    Some(spec.id)
                );
            }
        }
    }

    #[test]
    fn a_protocol_with_links_knows_how_to_read_them() {
        // Схема без разбора означает ссылку, которая опознаётся и тут же
        // отвергается, — худший из возможных ответов.
        for spec in ALL {
            assert_eq!(
                !spec.schemes.is_empty(),
                spec.takes_links(),
                "`{}`: схемы есть, а разбора нет",
                spec.id
            );
        }
    }

    #[test]
    fn every_protocol_asks_for_a_server() {
        // Поле адреса — единственное, что показывается в списке профилей
        // (`screens::servers::server_of`), и без него строка пуста.
        for spec in ALL {
            let server = spec
                .fields
                .iter()
                .find(|field| field.key == "server")
                .expect("нет поля адреса");
            assert_eq!(server.path, &["server"], "адрес `{}` не там", spec.id);
            assert!(
                server.required.is_some(),
                "адрес `{}` необязателен",
                spec.id
            );
        }
    }

    #[test]
    fn field_names_do_not_repeat_inside_a_protocol() {
        // По имени поля черновик ищет значение; два поля с одним именем
        // означают, что второе правится, а показывается первое.
        for spec in ALL {
            let keys: HashSet<&str> = spec.fields.iter().map(|field| field.key).collect();
            assert_eq!(keys.len(), spec.fields.len(), "`{}`", spec.id);
        }
    }

    #[test]
    fn the_default_is_in_the_list() {
        assert!(ALL.iter().any(|spec| spec.id == DEFAULT.id));
    }
}
