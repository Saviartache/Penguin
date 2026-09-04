//! macOS: kill switch на pf.
//!
//! У pf есть якоря — именованные наборы правил, которые можно заменять, не
//! трогая остальные. Свои правила клиент держит в якоре `penguin`, и снятие
//! означает убрать из него всё.
//!
//! Одного якоря, однако, мало: пока на него нет ссылки в `/etc/pf.conf`, pf
//! его не читает. Ссылку приходится дописывать, а прежний файл — сохранять,
//! иначе вернуть настройки пользователя будет неоткуда.
//!
//! Отсюда и восстановление после падения: сохранённый файл переживает смерть
//! клиента, и служба при следующем запуске возвращает его на место.

use std::path::Path;

use crate::command;
use crate::error::{PlatformError, PlatformResult};
use crate::firewall::{FirewallRules, lan_networks};

/// Программа, которой задаются правила.
const PFCTL: &str = "/sbin/pfctl";

/// Имя якоря. Своё: чужие правила клиент не трогает.
const ANCHOR: &str = "penguin";

/// Файл настроек pf.
const PF_CONF: &str = "/etc/pf.conf";

/// Куда сохраняется прежний файл настроек.
///
/// Рядом с ним же и по соседству с настройками pf: так его найдёт и человек,
/// которому пришлось разбираться руками.
const PF_CONF_BACKUP: &str = "/etc/pf.conf.penguin-backup";

/// Файл с правилами якоря.
const ANCHOR_FILE: &str = "/etc/pf.anchors/penguin";

/// Включает запрет.
pub fn engage(rules: &FirewallRules) -> PlatformResult<()> {
    // Настройки, оставшиеся от прошлого запуска, возвращаются на место до
    // того, как поверх них лягут новые: иначе ссылка на якорь удвоится, а
    // сохранённым файлом станет уже наш собственный.
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
    // Включение уже включённого pf — не ошибка, но и не повод падать: он
    // отвечает предупреждением, а не отказом.
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

/// Возвращает настройки pf, какими они были.
///
/// Вызывается и при снятии, и при старте службы: сохранённый файл переживает
/// падение клиента, а вместе с ним переживает и запрет исходящего трафика.
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

/// Дописывает ссылку на якорь к настройкам pf.
///
/// Свободная функция с тестом: ссылка, дописанная дважды, означает якорь,
/// который pf прочитает дважды, а потерянная — kill switch, который не
/// действует, хотя клиент считает его включённым.
fn with_anchor(original: &str) -> String {
    if original.contains(&format!("anchor \"{ANCHOR}\"")) {
        return original.to_owned();
    }

    let mut text = original.to_owned();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    // В конец: pf требует, чтобы правила фильтрации шли после трансляции, а
    // ссылка на якорь — правило фильтрации.
    text.push_str(&format!("anchor \"{ANCHOR}\"\n"));
    text.push_str(&format!(
        "load anchor \"{ANCHOR}\" from \"{ANCHOR_FILE}\"\n"
    ));
    text
}

/// Правила якоря.
///
/// Свободная функция с тестом: ошибка здесь означает либо утечку трафика мимо
/// тоннеля, либо машину без сети.
fn ruleset(rules: &FirewallRules) -> String {
    let mut text = String::with_capacity(512);

    // Запрет идёт первым, а разрешения — с `quick`: у pf выигрывает последнее
    // подошедшее правило, но `quick` прекращает разбор на месте.
    text.push_str("block drop out all\n");
    // Петля — первым делом: без неё перестанут работать и сам клиент, и
    // половина приложений на машине.
    text.push_str("pass out quick on lo0 all\n");

    if let Some(subnet) = &rules.tunnel_subnet {
        // Трафик тоннеля опознаётся по адресу источника: пакет, ушедший в
        // адаптер, получает его из этой подсети, куда бы ни шёл дальше.
        text.push_str(&format!("pass out quick from {subnet} to any\n"));
    }

    for address in &rules.allow_addresses {
        // Прежде всего сам сервер: без него тоннель, ради которого kill
        // switch и включён, не поднимется.
        text.push_str(&format!("pass out quick to {address}\n"));
    }

    if rules.allow_lan {
        for network in lan_networks() {
            text.push_str(&format!("pass out quick to {network}\n"));
        }
    }

    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_not_allowed_is_dropped() {
        // Запрет по умолчанию — весь смысл kill switch.
        let text = ruleset(&FirewallRules::default());
        assert!(text.starts_with("block drop out all"), "{text}");
    }

    #[test]
    fn permissions_stop_the_search() {
        // Без `quick` победило бы последнее подошедшее правило, а запрет
        // стоит первым только по порядку чтения.
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
    fn loopback_is_always_allowed() {
        let text = ruleset(&FirewallRules::default());
        assert!(text.contains("pass out quick on lo0 all"), "{text}");
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
        // Дважды дописанная ссылка означает якорь, прочитанный дважды.
        let original = "scrub-anchor \"com.apple/*\"\n";
        let once = with_anchor(original);
        assert_eq!(with_anchor(&once), once);
        assert_eq!(once.matches("anchor \"penguin\"").count(), 2, "{once}");
    }

    #[test]
    fn a_file_without_a_final_newline_is_still_valid() {
        // Иначе ссылка приклеится к последней строке настроек, и pf
        // откажется читать файл целиком.
        let text = with_anchor("anchor \"com.apple/*\"");
        assert!(text.contains("\nanchor \"penguin\"\n"), "{text}");
    }
}
