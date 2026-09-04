//! Linux: kill switch на nftables.
//!
//! Правила живут в **своей** таблице `inet penguin` и ничего чужого не
//! трогают. Это и есть весь откат: `nft delete table inet penguin` убирает всё
//! разом, а таблицы, заведённые системой или пользователем, остаются как были.
//!
//! Отсюда же и восстановление после падения: таблица переживает смерть
//! клиента, но не переживает одной команды при следующем запуске службы.

use crate::command;
use crate::error::{PlatformError, PlatformResult};
use crate::firewall::{FirewallRules, lan_networks};

/// Программа, которой задаются правила.
const NFT: &str = "nft";

/// Имя таблицы. Своё: чужие правила клиент не трогает.
const TABLE: &str = "penguin";

/// Включает запрет.
pub fn engage(rules: &FirewallRules) -> PlatformResult<()> {
    if !command::exists(NFT) {
        return Err(PlatformError::Firewall(format!(
            "не найдена программа `{NFT}`: установите пакет nftables"
        )));
    }

    // Таблица от прошлого запуска снимается молча: она могла остаться от
    // упавшего клиента, и это не ошибка, а то, ради чего снятие и делается.
    let _ = disengage();

    command::feed(NFT, &["-f", "-"], &ruleset(rules))
        .map_err(|err| err.into_error(PlatformError::Firewall, "правила брандмауэра"))?;

    tracing::info!("kill switch включён");
    Ok(())
}

/// Снимает запрет.
pub fn disengage() -> PlatformResult<()> {
    if !command::exists(NFT) {
        // Программы нет — значит, и правил наших в системе нет.
        return Ok(());
    }

    // `destroy` не ругается на отсутствующую таблицу, но есть он не везде;
    // отсутствие таблицы при `delete` — не ошибка, а обычный исход.
    if command::run(NFT, &["delete", "table", "inet", TABLE]).is_err() {
        tracing::debug!("снимать было нечего");
    }
    Ok(())
}

/// Правила в виде, который читает `nft -f`.
///
/// Свободная функция с тестом: ошибка здесь означает либо утечку трафика мимо
/// тоннеля, либо машину без сети — и то и другое пользователь свяжет с чем
/// угодно, только не с одной строкой в наборе правил.
fn ruleset(rules: &FirewallRules) -> String {
    let mut text = String::with_capacity(512);

    text.push_str(&format!("table inet {TABLE} {{\n"));
    text.push_str("  chain output {\n");
    // `priority 0` и `policy drop`: всё, что не разрешено ниже, наружу не
    // уходит.
    text.push_str("    type filter hook output priority 0; policy drop;\n");
    // Петля — первым делом: без неё перестанут работать и сам клиент, и
    // половина приложений на машине.
    text.push_str("    oifname \"lo\" accept\n");

    if let Some(subnet) = &rules.tunnel_subnet {
        // Трафик тоннеля опознаётся по адресу источника: пакет, ушедший в
        // адаптер, получает его из этой подсети, куда бы ни шёл дальше.
        text.push_str(&format!("    ip saddr {subnet} accept\n"));
    }

    for address in &rules.allow_addresses {
        // Прежде всего сам сервер: без него тоннель, ради которого kill
        // switch и включён, не поднимется.
        let family = if address.is_ipv4() { "ip" } else { "ip6" };
        text.push_str(&format!("    {family} daddr {address} accept\n"));
    }

    if rules.allow_lan {
        for network in lan_networks() {
            let family = if network.contains(':') { "ip6" } else { "ip" };
            text.push_str(&format!("    {family} daddr {network} accept\n"));
        }
    }

    text.push_str("  }\n}\n");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_not_allowed_is_dropped() {
        // Правило по умолчанию — весь смысл kill switch. `accept` здесь
        // означал бы защиту, которая ничего не защищает.
        let text = ruleset(&FirewallRules::default());
        assert!(text.contains("policy drop"), "{text}");
    }

    #[test]
    fn loopback_is_always_allowed() {
        // Иначе перестанут работать и сам клиент, и половина приложений.
        let text = ruleset(&FirewallRules::default());
        assert!(text.contains("oifname \"lo\" accept"), "{text}");
    }

    #[test]
    fn the_tunnel_is_recognised_by_its_source() {
        // Пакет, ушедший в адаптер, получает адрес источника из служебной
        // подсети — куда бы он ни шёл дальше.
        let text = ruleset(&FirewallRules {
            tunnel_subnet: Some("198.18.0.0/15".to_owned()),
            ..FirewallRules::default()
        });
        assert!(text.contains("ip saddr 198.18.0.0/15 accept"), "{text}");
    }

    #[test]
    fn the_server_gets_through() {
        // Иначе тоннель заглушит сам себя.
        let text = ruleset(&FirewallRules {
            allow_addresses: vec!["203.0.113.5".parse().expect("адрес")],
            ..FirewallRules::default()
        });
        assert!(text.contains("ip daddr 203.0.113.5 accept"), "{text}");
    }

    #[test]
    fn an_ipv6_server_gets_an_ipv6_rule() {
        // Семейство в правиле должно совпадать с адресом, иначе `nft`
        // откажется читать набор целиком — и kill switch не включится вовсе.
        let text = ruleset(&FirewallRules {
            allow_addresses: vec!["2001:db8::1".parse().expect("адрес")],
            ..FirewallRules::default()
        });
        assert!(text.contains("ip6 daddr 2001:db8::1 accept"), "{text}");
    }

    #[test]
    fn the_local_network_is_opened_only_on_request() {
        let closed = ruleset(&FirewallRules::default());
        assert!(!closed.contains("192.168.0.0/16"), "{closed}");

        let opened = ruleset(&FirewallRules {
            allow_lan: true,
            ..FirewallRules::default()
        });
        assert!(
            opened.contains("ip daddr 192.168.0.0/16 accept"),
            "{opened}"
        );
    }

    #[test]
    fn the_ruleset_is_balanced() {
        // Незакрытая скобка означает набор, который `nft` не прочтёт, — то
        // есть kill switch, который не включился.
        let text = ruleset(&FirewallRules {
            tunnel_subnet: Some("198.18.0.0/15".to_owned()),
            allow_lan: true,
            allow_addresses: vec!["203.0.113.5".parse().expect("адрес")],
        });
        assert_eq!(
            text.matches('{').count(),
            text.matches('}').count(),
            "{text}"
        );
    }
}
