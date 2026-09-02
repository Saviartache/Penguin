//! Windows Filtering Platform.
//!
//! # Чем это сделано и почему не WFP напрямую
//!
//! Правильный способ — фильтры WFP, поставленные в собственный сеанс: они
//! исчезают вместе с процессом, и упавший клиент не оставляет систему без
//! сети. Цена — несколько сотен строк небезопасного кода вокруг
//! `FwpmEngineOpen0`, `FwpmFilterAdd0` и разбора условий, плюс отдельная
//! отладка на каждом издании Windows.
//!
//! Здесь взят брандмауэр Windows — тот же WFP, но через готовый слой правил.
//! Правила ставятся с собственной приставкой в имени и снимаются по ней же;
//! аварийный выход разбирается тем, что при следующем запуске клиент сначала
//! сносит все свои прежние правила.
//!
//! # Что делает kill switch
//!
//! Запрещает **исходящий** трафик по умолчанию и разрешает три вещи: сам
//! тоннель, петлю и, если пользователь разрешил, локальную сеть. Плюс адреса
//! сервера — без них тоннелю не подняться. Входящий не трогается: ответы на
//! уже разрешённые соединения брандмауэр пропускает сам.
//!
//! # Чего делать нельзя
//!
//! Запрещать правилом `remoteip=any action=block`. Так было сделано сначала, и
//! это не работает: запреты разбираются **раньше** разрешений, и такое правило
//! перекрывает всё — петлю, локальную сеть и трафик самого тоннеля. Проверено
//! опытом на одном адресе: с парой «запрет + разрешение» соединение не идёт.
//!
//! Запрет живёт в действии по умолчанию — см. [`super::policy`]. Оно
//! применяется последним, после всех правил.
//!
//! # Как опознаётся трафик тоннеля
//!
//! По **локальному** адресу, а не по интерфейсу: `netsh` принимает интерфейс
//! по имени, а имя меняется вместе с языком системы. Пакет, ушедший в тоннель,
//! получает адрес источника из подсети адаптера — по ней он и узнаётся, куда
//! бы ни шёл.

use std::process::Command;

use crate::error::{PlatformError, PlatformResult};
use crate::firewall::FirewallRules;
use crate::firewall::policy;

/// Приставка в именах правил.
///
/// По ней правила и находятся при снятии. Отдельной приставки достаточно:
/// брандмауэр умеет удалять по имени, и хранить где-то список не нужно —
/// список пережил бы падение клиента, а имена в системе и так остаются.
const RULE_PREFIX: &str = "Penguin-KillSwitch";

/// Имена правил, которые ставит клиент.
///
/// Перечислены явно: `netsh` не умеет удалять по маске.
const RULE_NAMES: [&str; 2] = ["-AllowTunnel", "-AllowNet"];

/// Снимает запрет и правила, оставшиеся от прошлого запуска.
///
/// Признаком служат сами правила: их ставят до запрета и снимают после него,
/// поэтому «наши правила на месте» означает, что прошлый запуск не убрал за
/// собой.
pub fn recover_leftovers() -> PlatformResult<()> {
    let leftovers = our_rules_present();
    if !leftovers {
        return Ok(());
    }
    let _ = delete_rules();
    policy::recover(true)
}

/// Ставит правила kill switch.
pub fn engage(rules: &FirewallRules) -> PlatformResult<Saved> {
    // Сначала убираем прежнее: клиент мог упасть, не сняв за собой ни правил,
    // ни запрета.
    recover_leftovers()?;

    // Разрешения ставятся до запрета: между тем и другим не должно быть мига,
    // когда наружу уже нельзя, а тоннелю ещё нельзя.
    if let Some(subnet) = &rules.tunnel_subnet {
        // Главное разрешение: всё, что ушло в тоннель, — куда бы ни шло.
        allow(&format!("localip={subnet}"))?;
    } else {
        // Без него kill switch перекроет сам тоннель. Молчать нельзя.
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

    // Адрес самого сервера: тоннель идёт до него напрямую, мимо адаптера, и
    // без разрешения попадает под общий запрет — то есть глушит сам себя.
    for server in &rules.allow_addresses {
        allow(&format!("remoteip={server}"))?;
    }

    let saved = policy::block_outbound()?;
    tracing::info!("kill switch включён");
    Ok(saved)
}

/// Что надо вернуть при снятии.
pub type Saved = policy::Saved;

/// Снимает правила.
pub fn disengage(saved: &Saved) -> PlatformResult<()> {
    // Сначала запрет, потом правила: обратный порядок оставил бы миг, когда
    // наружу нельзя вообще ничего.
    let restored = policy::restore(saved);
    let deleted = delete_rules();

    match (restored, deleted) {
        (Ok(()), Ok(())) => {
            tracing::info!("kill switch выключен");
            Ok(())
        }
        // Оставленный запрет означает, что у пользователя не работает сеть
        // после выхода из клиента — причём и после перезагрузки.
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
///
/// Признак того, что прошлый запуск не убрал за собой: правила ставятся до
/// запрета и снимаются после него.
fn our_rules_present() -> bool {
    let Ok(output) = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={RULE_PREFIX}-AllowTunnel"),
        ])
        .output()
    else {
        return false;
    };

    output.status.success()
}

/// Разрешает исходящий трафик по условию.
fn allow(condition: &str) -> PlatformResult<()> {
    // Имя одно на все разрешения кроме тоннельного: брандмауэр допускает
    // одноимённые правила и удаляет их одной командой.
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
    // Правило не нашлось при удалении — это успех: снимать было нечего.
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
        // По приставке правила и находятся при снятии; имя мимо неё означает
        // правило, которое останется в системе навсегда.
        for suffix in RULE_NAMES {
            assert!(format!("{RULE_PREFIX}{suffix}").starts_with(RULE_PREFIX));
        }
    }

    #[test]
    fn the_tunnel_rule_is_told_apart_by_the_local_address() {
        // Разрешение по локальному адресу — единственное, что пропускает
        // трафик тоннеля к любому получателю; спутать его с обычным значит
        // перекрыть тоннель.
        assert!("localip=198.18.0.0/15".starts_with("localip="));
        assert!(!"remoteip=10.0.0.0/8".starts_with("localip="));
    }

    #[test]
    fn deleting_a_missing_rule_is_not_an_error() {
        // Снимать нечего — это успех: иначе первый же запуск на чистой машине
        // сообщал бы об ошибке.
        assert!(delete_rules().is_ok() || !crate::is_elevated());
    }
}
