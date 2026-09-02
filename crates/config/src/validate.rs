//! Проверки, которые serde не выражает: непротиворечивость правил, диапазоны,
//! ссылки на несуществующие профили.
//!
//! Проверка идёт и при чтении, и при записи. При чтении — чтобы клиент не
//! поднялся с настройками, которые он всё равно не сможет применить; при
//! записи — чтобы интерфейс не сохранил то, что сам же потом не прочитает.

use std::collections::HashSet;

use penguin_core::id::OutboundId;

use crate::error::{ConfigError, ConfigResult};
use crate::schema::RootConfig;
use crate::schema::rule::RuleAction;

/// Проверяет настройки целиком.
pub fn validate(config: &RootConfig) -> ConfigResult<()> {
    validate_profiles(config)?;
    validate_rules(config)?;
    validate_network(config)?;
    Ok(())
}

fn validate_profiles(config: &RootConfig) -> ConfigResult<()> {
    let mut seen = HashSet::new();
    for profile in &config.profiles {
        if profile.id.as_str().is_empty() {
            return Err(ConfigError::invalid("profiles.id", "пустой идентификатор"));
        }
        // Имя прямого выхода занято движком: профиль превращается в
        // направление один в один, и профиль с таким именем сделал бы
        // невозможным правило «напрямую».
        if profile.id.as_str() == OutboundId::DIRECT {
            return Err(ConfigError::invalid(
                "profiles.id",
                format!("идентификатор `{}` занят прямым выходом", profile.id),
            ));
        }
        if !seen.insert(profile.id.clone()) {
            return Err(ConfigError::invalid(
                "profiles.id",
                format!("повторяется идентификатор `{}`", profile.id),
            ));
        }
        if profile.outbound.protocol.is_empty() {
            return Err(ConfigError::invalid(
                format!("profiles.{}.outbound.protocol", profile.id),
                "не указан протокол",
            ));
        }
        if let Some(path) = first_null(&profile.outbound.params, "") {
            // Настройки лежат в TOML, а в нём пустого значения не существует
            // вовсе. Без этой проверки профиль сохраняется, `toml` отвечает
            // `unsupported unit type`, и человек читает эту фразу вместо
            // «незаполненное поле уберите, а не оставляйте пустым».
            return Err(ConfigError::invalid(
                format!("profiles.{}.outbound{path}", profile.id),
                "пустое значение: в настройках его быть не может — поле либо                  заполняют, либо не пишут вовсе",
            ));
        }
    }

    if let Some(active) = &config.active_profile
        && config.profile(active).is_none()
    {
        return Err(ConfigError::invalid(
            "active_profile",
            format!("нет профиля с идентификатором `{active}`"),
        ));
    }

    Ok(())
}

/// Путь до первого пустого значения в параметрах протокола.
///
/// Свободная функция с тестом: параметры протокола окно не разбирает, и
/// пустое значение внутри них — единственное, что может сломать запись всех
/// настроек целиком.
fn first_null(value: &serde_json::Value, path: &str) -> Option<String> {
    match value {
        serde_json::Value::Null => Some(path.to_owned()),
        serde_json::Value::Object(map) => map
            .iter()
            .find_map(|(name, inner)| first_null(inner, &format!("{path}.{name}"))),
        serde_json::Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(index, inner)| first_null(inner, &format!("{path}[{index}]"))),
        _ => None,
    }
}

fn validate_rules(config: &RootConfig) -> ConfigResult<()> {
    let known: HashSet<&str> = config.profiles.iter().map(|p| p.id.as_str()).collect();
    let mut seen = HashSet::new();

    for rule in &config.routing.rules {
        if rule.id.is_empty() {
            return Err(ConfigError::invalid(
                "routing.rules.id",
                "пустой идентификатор",
            ));
        }
        if !seen.insert(rule.id.as_str()) {
            return Err(ConfigError::invalid(
                "routing.rules.id",
                format!("повторяется идентификатор `{}`", rule.id),
            ));
        }
        // Правило, ссылающееся на удалённый профиль, — самая обидная ошибка:
        // оно молча перестаёт работать, и трафик уходит по умолчанию режима.
        if let RuleAction::Tunnel {
            profile: Some(profile),
        } = &rule.action
            && !known.contains(profile.as_str())
        {
            return Err(ConfigError::invalid(
                format!("routing.rules.{}.action", rule.id),
                format!("нет профиля с идентификатором `{profile}`"),
            ));
        }
    }

    Ok(())
}

fn validate_network(config: &RootConfig) -> ConfigResult<()> {
    let tun = &config.network.tun;

    // Нижняя граница — обязательный минимум IPv6; верхняя — обычный кадр
    // Ethernet. За этими пределами пакеты либо не пройдут по пути, либо
    // будут дробиться на каждом узле.
    if !(1280..=1500).contains(&tun.mtu) {
        return Err(ConfigError::invalid(
            "network.tun.mtu",
            format!("ожидается 1280..=1500, указано {}", tun.mtu),
        ));
    }
    if tun.ipv4_prefix > 32 {
        return Err(ConfigError::invalid(
            "network.tun.ipv4_prefix",
            format!("ожидается 0..=32, указано {}", tun.ipv4_prefix),
        ));
    }
    if tun.ipv6_prefix > 128 {
        return Err(ConfigError::invalid(
            "network.tun.ipv6_prefix",
            format!("ожидается 0..=128, указано {}", tun.ipv6_prefix),
        ));
    }
    if tun.name.trim().is_empty() {
        return Err(ConfigError::invalid(
            "network.tun.name",
            "пустое имя адаптера",
        ));
    }

    // Прокси, слушающий не на петле и без пароля, открыт всей сети — включая
    // ту, от которой пользователь и прячется.
    for (field, inbound) in [
        ("network.socks", &config.network.socks),
        ("network.http", &config.network.http),
    ] {
        let Some(inbound) = inbound else { continue };
        if !inbound.listen.ip().is_loopback() && inbound.auth.is_none() {
            return Err(ConfigError::invalid(
                field,
                "прокси слушает не на localhost и без пароля — это открытый прокси для всей сети",
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use penguin_core::id::ProfileId;
    use serde_json::json;

    use super::*;
    use crate::schema::network::InboundConfig;
    use crate::schema::outbound::RawOutbound;
    use crate::schema::profile::Profile;
    use crate::schema::rule::{Condition, Leaf, RuleConfig};

    fn profile(id: &str) -> Profile {
        Profile::new(id, id, RawOutbound::new("hysteria2", json!({})))
    }

    #[test]
    fn accepts_defaults() {
        validate(&RootConfig::default()).expect("умолчания корректны");
    }

    #[test]
    fn rejects_duplicate_profiles() {
        let mut config = RootConfig::default();
        config.profiles.push(profile("home"));
        config.profiles.push(profile("home"));
        assert!(validate(&config).is_err());
    }

    #[test]
    fn rejects_reserved_profile_id() {
        let mut config = RootConfig::default();
        config.profiles.push(profile("direct"));
        assert!(validate(&config).is_err());
    }

    #[test]
    fn rejects_dangling_active_profile() {
        let mut config = RootConfig::default();
        config.profiles.push(profile("home"));
        config.active_profile = Some(ProfileId::new("office"));
        assert!(validate(&config).is_err());
    }

    #[test]
    fn rejects_rule_pointing_at_missing_profile() {
        let mut config = RootConfig::default();
        config.profiles.push(profile("home"));
        config.routing.rules.push(RuleConfig {
            id: "r1".to_owned(),
            name: String::new(),
            enabled: true,
            priority: 0,
            when: Condition::Leaf(Leaf::DestPort(vec![443])),
            action: RuleAction::Tunnel {
                profile: Some("office".to_owned()),
            },
        });
        assert!(validate(&config).is_err());
    }

    #[test]
    fn rejects_open_proxy() {
        let mut config = RootConfig::default();
        config.network.socks = Some(InboundConfig {
            listen: "0.0.0.0:1080".parse().expect("адрес"),
            auth: None,
        });
        assert!(validate(&config).is_err());
    }

    #[test]
    fn rejects_impossible_mtu() {
        let mut config = RootConfig::default();
        config.network.tun.mtu = 9000;
        assert!(validate(&config).is_err());
    }
}
