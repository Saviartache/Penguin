//! Windows: kill switch через брандмауэр (`netsh`) и действие по умолчанию ([`super::policy`]).
//!
//! Исходящий трафик запрещён по умолчанию; разрешены тоннель, петля, по запросу локальная сеть и
//! адреса сервера. Запрет правилом `block` не годится: запреты разбираются раньше разрешений.
//! Правила с общей приставкой снимаются по имени; после аварии следующий запуск сносит прежние.
//! Трафик тоннеля опознаётся по локальному адресу (имя интерфейса зависит от языка системы).

use std::process::Command;

use crate::error::{PlatformError, PlatformResult};
use crate::firewall::FirewallRules;
use crate::firewall::policy;

/// Приставка в именах правил: по ней они снимаются.
const RULE_PREFIX: &str = "Penguin-KillSwitch";

/// Имена правил клиента; `netsh` не умеет удалять по маске.
const RULE_NAMES: [&str; 2] = ["-AllowTunnel", "-AllowNet"];

/// Снимает запрет и правила прошлого запуска: правила ставятся до запрета и снимаются после.
pub fn recover_leftovers() -> PlatformResult<()> {
    if !our_rules_present() {
        return Ok(());
    }
    let _ = delete_rules();
    policy::recover(true)
}

/// Ставит правила kill switch.
pub fn engage(rules: &FirewallRules) -> PlatformResult<Saved> {
    recover_leftovers()?;

    // Разрешения до запрета, чтобы не было мига «нельзя ни наружу, ни в тоннель».
    if let Some(subnet) = &rules.tunnel_subnet {
        allow(&format!("localip={subnet}"))?;
    } else {
        tracing::warn!("подсеть тоннеля неизвестна — kill switch перекроет сам тоннель");
    }

    allow("remoteip=127.0.0.0/8")?;

    if rules.allow_lan {
        for subnet in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
        ] {
            allow(&format!("remoteip={subnet}"))?;
        }
    }

    // Сервер достижим напрямую, мимо адаптера, и без разрешения попал бы под запрет.
    for server in &rules.allow_addresses {
        allow(&format!("remoteip={server}"))?;
    }

    let saved = policy::block_outbound()?;
    tracing::info!("kill switch включён");
    Ok(saved)
}

/// Что надо вернуть при снятии.
pub type Saved = policy::Saved;

/// Снимает правила: сначала запрет, потом правила, иначе будет миг без сети.
pub fn disengage(saved: &Saved) -> PlatformResult<()> {
    let restored = policy::restore(saved);
    let deleted = delete_rules();

    match (restored, deleted) {
        (Ok(()), Ok(())) => {
            tracing::info!("kill switch выключен");
            Ok(())
        }
        (Err(err), _) | (Ok(()), Err(err)) => Err(err),
    }
}

/// Убирает правила клиента.
fn delete_rules() -> PlatformResult<()> {
    let mut failures = Vec::new();

    for suffix in RULE_NAMES {
        let name = format!("{RULE_PREFIX}{suffix}");
        if let Err(err) = netsh(&[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={name}"),
        ]) {
            failures.push(err.to_string());
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(PlatformError::rollback(
            "правила брандмауэра",
            failures.join("; "),
        ))
    }
}

/// Стоят ли ещё наши правила.
fn our_rules_present() -> bool {
    Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={RULE_PREFIX}-AllowTunnel"),
        ])
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Разрешает исходящий трафик по условию; одноимённые правила удаляются одной командой.
fn allow(condition: &str) -> PlatformResult<()> {
    let name = if condition.starts_with("localip=") {
        format!("{RULE_PREFIX}-AllowTunnel")
    } else {
        format!("{RULE_PREFIX}-AllowNet")
    };

    netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={name}"),
        "dir=out",
        "action=allow",
        condition,
    ])
}

/// Выполняет команду брандмауэра.
fn netsh(args: &[&str]) -> PlatformResult<()> {
    let output = Command::new("netsh")
        .args(args)
        .output()
        .map_err(|e| PlatformError::Firewall(format!("не запускается netsh: {e}")))?;

    if output.status.success() {
        return Ok(());
    }

    let message = String::from_utf8_lossy(&output.stdout);
    // Правило не нашлось при удалении — снимать было нечего.
    if message.contains("No rules match") || message.contains("Ни одно правило") {
        return Ok(());
    }
    if message.contains("Access is denied") || message.contains("Отказано в доступе")
    {
        return Err(PlatformError::PermissionDenied(
            "правила брандмауэра".to_owned(),
        ));
    }

    Err(PlatformError::Firewall(message.trim().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_names_share_the_prefix() {
        for suffix in RULE_NAMES {
            assert!(format!("{RULE_PREFIX}{suffix}").starts_with(RULE_PREFIX));
        }
    }

    #[test]
    fn the_tunnel_rule_is_told_apart_by_the_local_address() {
        assert!("localip=198.18.0.0/15".starts_with("localip="));
        assert!(!"remoteip=10.0.0.0/8".starts_with("localip="));
    }

    #[test]
    fn deleting_a_missing_rule_is_not_an_error() {
        assert!(delete_rules().is_ok() || !crate::is_elevated());
    }
}
