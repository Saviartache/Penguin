//! Linux: kill switch на nftables в своей таблице `inet penguin`; откат — удаление этой таблицы.
//! Таблица переживает смерть клиента, но не следующий запуск службы.

use std::fmt::Write;

use crate::command;
use crate::error::{PlatformError, PlatformResult};
use crate::firewall::{FirewallRules, lan_networks};

/// Программа, которой задаются правила.
const NFT: &str = "nft";

/// Имя таблицы; чужие правила клиент не трогает.
const TABLE: &str = "penguin";

/// Включает запрет.
pub fn engage(rules: &FirewallRules) -> PlatformResult<()> {
    if !command::exists(NFT) {
        return Err(PlatformError::Firewall(format!(
            "не найдена программа `{NFT}`: установите пакет nftables"
        )));
    }

    // Таблица могла остаться от упавшего клиента.
    let _ = disengage();

    command::feed(NFT, &["-f", "-"], &ruleset(rules))
        .map_err(|err| err.into_error(PlatformError::Firewall, "правила брандмауэра"))?;

    tracing::info!("kill switch включён");
    Ok(())
}

/// Снимает запрет.
pub fn disengage() -> PlatformResult<()> {
    if !command::exists(NFT) {
        return Ok(());
    }

    // `delete` на отсутствующую таблицу — обычный исход.
    if command::run(NFT, &["delete", "table", "inet", TABLE]).is_err() {
        tracing::debug!("снимать было нечего");
    }
    Ok(())
}

/// Правила в виде для `nft -f`.
fn ruleset(rules: &FirewallRules) -> String {
    let mut text = String::with_capacity(512);

    let _ = writeln!(text, "table inet {TABLE} {{");
    text.push_str("  chain output {\n");
    text.push_str("    type filter hook output priority 0; policy drop;\n");
    text.push_str("    oifname \"lo\" accept\n");
    // Служба (root) сама шлёт «напрямую» и загрузочный DNS мимо тоннеля.
    text.push_str("    meta skuid 0 accept\n");

    // Трафик тоннеля опознаётся по адресу источника из служебной подсети.
    if let Some(subnet) = &rules.tunnel_subnet {
        let _ = writeln!(text, "    ip saddr {subnet} accept");
    }

    for address in &rules.allow_addresses {
        let family = if address.is_ipv4() { "ip" } else { "ip6" };
        let _ = writeln!(text, "    {family} daddr {address} accept");
    }

    if rules.allow_lan {
        for network in lan_networks() {
            let family = if network.contains(':') { "ip6" } else { "ip" };
            let _ = writeln!(text, "    {family} daddr {network} accept");
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
        let text = ruleset(&FirewallRules::default());
        assert!(text.contains("policy drop"), "{text}");
    }

    #[test]
    fn loopback_is_always_allowed() {
        let text = ruleset(&FirewallRules::default());
        assert!(text.contains("oifname \"lo\" accept"), "{text}");
    }

    #[test]
    fn the_service_own_direct_traffic_passes() {
        let text = ruleset(&FirewallRules::default());
        assert!(text.contains("meta skuid 0 accept"), "{text}");
    }

    #[test]
    fn the_tunnel_is_recognised_by_its_source() {
        let text = ruleset(&FirewallRules {
            tunnel_subnet: Some("198.18.0.0/15".to_owned()),
            ..FirewallRules::default()
        });
        assert!(text.contains("ip saddr 198.18.0.0/15 accept"), "{text}");
    }

    #[test]
    fn the_server_gets_through() {
        let text = ruleset(&FirewallRules {
            allow_addresses: vec!["203.0.113.5".parse().expect("адрес")],
            ..FirewallRules::default()
        });
        assert!(text.contains("ip daddr 203.0.113.5 accept"), "{text}");
    }

    #[test]
    fn an_ipv6_server_gets_an_ipv6_rule() {
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
