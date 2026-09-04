//! Проверки значений полей, общие всем протоколам.
//!
//! Разбор идёт типами [`penguin_core`] — теми же, которыми пользуются сами
//! протоколы. Позвать протокол напрямую было бы точнее, но окно не имеет права
//! о нём знать: `protocols/*` подключает один только `engine` (см. `AGENTS.md`),
//! иначе каждый новый протокол правил бы ещё и интерфейс.
//!
//! Проверяется здесь только то, что видно без сети и без разбора настроек
//! протокола целиком. Настоящую проверку делает сам протокол — окно ловит
//! опечатку в поле до того, как человек нажмёт «Сохранить», а не вместо него.

use penguin_core::endpoint::ServerEndpoint;

/// Адрес сервера: `example.com:443`, `[2001:db8::1]:443`, `host:20000-30000`.
///
/// Диапазон портов пропускается намеренно: он законен у Hysteria 2 и
/// незаконен у прокси, но это уже разница между протоколами, и отвечает за неё
/// протокол — с объяснением, которого у окна нет.
pub fn server_address(raw: &str) -> Result<(), String> {
    raw.parse::<ServerEndpoint>()
        .map(|_| ())
        .map_err(|_| crate::i18n::s().bad_server.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_checked_the_way_the_protocols_check_them() {
        server_address("example.com:443").expect("имя и порт");
        server_address("example.com:20000-30000").expect("диапазон портов");
        server_address("[2001:db8::1]:443").expect("IPv6 в скобках");
        server_address("1.2.3.4:443").expect("адрес и порт");
        server_address("127.0.0.1:1080").expect("прокси на этой же машине");
    }

    #[test]
    fn an_address_without_a_port_is_refused() {
        // Профиль, который сохраняется, но не подключается, — худший исход:
        // виновата будет «служба».
        assert!(server_address("example.com").is_err());
        assert!(server_address("[2001:db8::1]").is_err());
        assert!(server_address("example.com:абв").is_err());
        assert!(server_address("просто-текст").is_err());
        assert!(server_address("").is_err());
    }

    #[test]
    fn the_reason_is_something_a_person_can_read() {
        // Текст показывается как есть: разбирать код ошибки в интерфейсе
        // всё равно некому.
        let reason = server_address("нет порта").expect_err("не разбирается");
        assert_eq!(reason, crate::i18n::s().bad_server);
    }
}
