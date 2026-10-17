//! macOS: kill switch на pf в якоре `penguin`.
//!
//! pf читает якорь только при ссылке на него в `/etc/pf.conf`: ссылка дописывается, прежний файл
//! сохраняется и возвращается на место при снятии и при следующем запуске службы.

use std::fmt::Write;
use std::path::Path;

use crate::command;
use crate::error::{PlatformError, PlatformResult};
use crate::firewall::{FirewallRules, lan_networks};

/// Программа, которой задаются правила.
const PFCTL: &str = "/sbin/pfctl";

/// Имя якоря; чужие правила клиент не трогает.
const ANCHOR: &str = "penguin";

/// Файл настроек pf.
const PF_CONF: &str = "/etc/pf.conf";

/// Куда сохраняется прежний файл настроек.
const PF_CONF_BACKUP: &str = "/etc/pf.conf.penguin-backup";

/// Файл с правилами якоря.
const ANCHOR_FILE: &str = "/etc/pf.anchors/penguin";

/// Включает запрет.
pub fn engage(rules: &FirewallRules) -> PlatformResult<()> {
    // Сначала вернуть настройки прошлого запуска: иначе ссылка на якорь удвоится.
    recover_leftovers()?;

    std::fs::write(ANCHOR_FILE, ruleset(rules))
        .map_err(|err| PlatformError::Firewall(format!("{ANCHOR_FILE}: {err}")))?;

    let original = std::fs::read_to_string(PF_CONF)
        .map_err(|err| PlatformError::Firewall(format!("{PF_CONF}: {err}")))?;
    std::fs::copy(PF_CONF, PF_CONF_BACKUP)
        .map_err(|err| PlatformError::Firewall(format!("{PF_CONF_BACKUP}: {err}")))?;
    std::fs::write(PF_CONF, with_anchor(&original))
        .map_err(|err| PlatformError::Firewall(format!("{PF_CONF}: {err}")))?;

    command::run(PFCTL, &["-f", PF_CONF])
        .map_err(|err| err.into_error(PlatformError::Firewall, "правила брандмауэра"))?;
    // Уже включённый pf отвечает предупреждением, а не отказом.
    if let Err(err) = command::run(PFCTL, &["-e"]) {
        tracing::debug!(?err, "pf уже был включён");
    }

    tracing::info!("kill switch включён");
    Ok(())
}

/// Снимает запрет.
pub fn disengage() -> PlatformResult<()> {
    recover_leftovers()
}

/// Возвращает настройки pf; сохранённый файл переживает падение клиента вместе с запретом.
pub fn recover_leftovers() -> PlatformResult<()> {
    if !Path::new(PF_CONF_BACKUP).exists() {
        return Ok(());
    }

    std::fs::copy(PF_CONF_BACKUP, PF_CONF)
        .map_err(|err| PlatformError::rollback("правила брандмауэра", err))?;
    std::fs::remove_file(PF_CONF_BACKUP)
        .map_err(|err| PlatformError::rollback("сохранённые правила брандмауэра", err))?;
    let _ = std::fs::remove_file(ANCHOR_FILE);

    command::run(PFCTL, &["-f", PF_CONF])
        .map_err(|err| err.into_error(PlatformError::Firewall, "правила брандмауэра"))?;

    tracing::info!("правила брандмауэра возвращены");
    Ok(())
}

/// Дописывает ссылку на якорь (один раз) в конец настроек: фильтрация идёт после трансляции.
fn with_anchor(original: &str) -> String {
    if original.contains(&format!("anchor \"{ANCHOR}\"")) {
        return original.to_owned();
    }

    let mut text = original.to_owned();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let _ = writeln!(text, "anchor \"{ANCHOR}\"");
    let _ = writeln!(text, "load anchor \"{ANCHOR}\" from \"{ANCHOR_FILE}\"");
    text
}

/// Правила якоря: запрет первым, разрешения с `quick` (разбор прекращается на месте).
fn ruleset(rules: &FirewallRules) -> String {
    let mut text = String::with_capacity(512);

    text.push_str("block drop out all\n");
    text.push_str("pass out quick on lo0 all\n");
    // Прямой выход и DNS службы: pf не различает процессов, служба — единственный свой root.
    text.push_str("pass out quick proto { tcp udp } all user root\n");

    // Трафик тоннеля опознаётся по адресу источника из служебной подсети.
    if let Some(subnet) = &rules.tunnel_subnet {
        let _ = writeln!(text, "pass out quick from {subnet} to any");
    }

    for address in &rules.allow_addresses {
        let _ = writeln!(text, "pass out quick to {address}");
    }

    if rules.allow_lan {
        for network in lan_networks() {
            let _ = writeln!(text, "pass out quick to {network}");
        }
    }

    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_not_allowed_is_dropped() {
        let text = ruleset(&FirewallRules::default());
        assert!(text.starts_with("block drop out all"), "{text}");
    }

    #[test]
    fn permissions_stop_the_search() {
        let text = ruleset(&FirewallRules {
            tunnel_subnet: Some("198.18.0.0/15".to_owned()),
            allow_lan: true,
            allow_addresses: vec!["203.0.113.5".parse().expect("адрес")],
        });
        for line in text.lines().filter(|line| line.starts_with("pass")) {
            assert!(line.contains("quick"), "правило без `quick`: {line}");
        }
    }

    #[test]
    fn an_ipv6_server_is_let_through_bare() {
        let text = ruleset(&FirewallRules {
            allow_addresses: vec!["2001:db8::1".parse().expect("адрес")],
            ..FirewallRules::default()
        });
        assert!(text.contains("pass out quick to 2001:db8::1\n"), "{text}");
    }

    #[test]
    fn loopback_is_always_allowed() {
        let text = ruleset(&FirewallRules::default());
        assert!(text.contains("pass out quick on lo0 all"), "{text}");
    }

    #[test]
    fn the_service_own_direct_traffic_passes() {
        let text = ruleset(&FirewallRules::default());
        assert!(
            text.contains("pass out quick proto { tcp udp } all user root"),
            "{text}"
        );
    }

    #[test]
    fn the_tunnel_is_recognised_by_its_source() {
        let text = ruleset(&FirewallRules {
            tunnel_subnet: Some("198.18.0.0/15".to_owned()),
            ..FirewallRules::default()
        });
        assert!(
            text.contains("pass out quick from 198.18.0.0/15 to any"),
            "{text}"
        );
    }

    #[test]
    fn the_anchor_is_referenced_once() {
        let original = "scrub-anchor \"com.apple/*\"\n";
        let once = with_anchor(original);
        assert_eq!(with_anchor(&once), once);
        assert_eq!(once.matches("anchor \"penguin\"").count(), 2, "{once}");
    }

    #[test]
    fn a_file_without_a_final_newline_is_still_valid() {
        let text = with_anchor("anchor \"com.apple/*\"");
        assert!(text.contains("\nanchor \"penguin\"\n"), "{text}");
    }
}
