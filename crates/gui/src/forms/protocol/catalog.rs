//! Все протоколы, какие окно умеет показать, в порядке списка выбора.

use crate::forms::protocol::spec::ProtocolSpec;
use crate::forms::protocol::{
    anytls, dpi, hysteria2, juicity, masque, masque_ip, naive, pingwin, shadowsocks, socks5,
    trojan, trusttunnel, tuic, vless, vmess, wireguard,
};

/// Протоколы в порядке показа; добавление — строка здесь и файл рядом.
pub static ALL: &[&ProtocolSpec] = &[
    // Свой протокол: сервер лежит в этом же дереве, DPI обходит сам.
    &pingwin::SPEC,
    // DPI: серверу нечего настраивать, лечит блокировку по имени узла.
    &dpi::SPEC,
    &wireguard::SPEC,
    &hysteria2::SPEC,
    &tuic::SPEC,
    &juicity::SPEC,
    &anytls::SPEC,
    &vless::SPEC,
    &vmess::SPEC,
    &trojan::SPEC,
    &shadowsocks::SPEC,
    &trusttunnel::SPEC,
    &naive::HTTP3,
    &naive::HTTP2,
    &masque::SPEC,
    &masque_ip::SPEC,
    &socks5::TLS,
    &socks5::SPEC,
];

/// Протокол формы, когда его не выбирали: тесты и пустое состояние.
pub static DEFAULT: &ProtocolSpec = &hysteria2::SPEC;

/// Описание по имени из настроек; `None` — профиль от новой версии, его
/// показывают, а не теряют ([`crate::forms::server::Draft`]).
pub fn by_id(id: &str) -> Option<&'static ProtocolSpec> {
    ALL.iter().copied().find(|spec| spec.id == id)
}

/// Описание по схеме ссылки без `://`: `hy2`, `socks5`.
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
        let ids: HashSet<&str> = ALL.iter().map(|spec| spec.id).collect();
        assert_eq!(ids.len(), ALL.len(), "повторяется имя протокола");

        let labels: HashSet<&str> = ALL.iter().map(|spec| spec.label).collect();
        assert_eq!(labels.len(), ALL.len(), "повторяется подпись протокола");
    }

    #[test]
    fn schemes_belong_to_one_protocol_each() {
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
    fn every_protocol_that_has_a_server_asks_for_its_address() {
        // Адрес показывается в списке профилей (`screens::servers::server_of`).
        // У режима DPI сервера нет: соединение идёт прямо к сайту.
        for spec in ALL.iter().filter(|spec| spec.id != dpi::SPEC.id) {
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
        for spec in ALL {
            let keys: HashSet<&str> = spec.fields.iter().map(|field| field.key).collect();
            assert_eq!(keys.len(), spec.fields.len(), "`{}`", spec.id);
        }
    }

    #[test]
    fn no_field_is_called_protocol() {
        // `RawOutbound` вынимает `protocol` до передачи параметров протоколу.
        for spec in ALL {
            for field in spec.fields {
                assert_ne!(
                    field.path.first(),
                    Some(&"protocol"),
                    "`{}`: поле `{}` заняло бы имя выбора протокола",
                    spec.id,
                    field.key
                );
            }
        }
    }

    #[test]
    fn the_default_is_in_the_list() {
        assert!(ALL.iter().any(|spec| spec.id == DEFAULT.id));
    }
}
