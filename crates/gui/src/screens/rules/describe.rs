//! Описание условий и действий правила словами.
//!
//! Только знаки, которые есть в ZedMono (см. [`crate::console`]): стрелка —
//! `->`, не `→`.

use penguin_config::schema::rule::{Condition, Leaf, RuleAction};

/// Подпись действия.
pub fn describe_action(action: &RuleAction) -> String {
    match action {
        RuleAction::Tunnel {
            profile: Some(profile),
        } => format!("{} -> {profile}", crate::i18n::s().action_tunnel),
        RuleAction::Tunnel { profile: None } => crate::i18n::s().action_tunnel.to_owned(),
        RuleAction::Direct => crate::i18n::s().action_direct.to_owned(),
        RuleAction::Block => crate::i18n::s().action_block.to_owned(),
    }
}

/// Описывает условие словами; в таблице важно узнать правило, не разобрать целиком.
pub fn describe_condition(condition: &Condition) -> String {
    match condition {
        // Не « и »: оно уже есть в «домены и поддомены».
        Condition::All { all } => join(all, ", "),
        Condition::Any { any } => join(any, " или "),
        Condition::Not { not } => format!("не {}", describe_condition(not)),
        Condition::Leaf(leaf) => describe_leaf(leaf),
    }
}

fn join(conditions: &[Condition], separator: &str) -> String {
    conditions
        .iter()
        .map(describe_condition)
        .collect::<Vec<_>>()
        .join(separator)
}

/// Все значения условия строками — для поиска: описание их только считает.
pub fn condition_values(condition: &Condition) -> Vec<String> {
    match condition {
        Condition::All { all: list } | Condition::Any { any: list } => {
            list.iter().flat_map(condition_values).collect()
        }
        Condition::Not { not } => condition_values(not),
        Condition::Leaf(leaf) => leaf_values(leaf),
    }
}

fn leaf_values(leaf: &Leaf) -> Vec<String> {
    match leaf {
        Leaf::ProcessPath(values)
        | Leaf::ProcessName(values)
        | Leaf::ProcessPathGlob(values)
        | Leaf::Domain(values)
        | Leaf::DomainSuffix(values)
        | Leaf::DomainKeyword(values)
        | Leaf::DomainRegex(values)
        | Leaf::DestIp(values)
        | Leaf::GeoIp(values)
        | Leaf::GeoSite(values)
        | Leaf::Network(values)
        | Leaf::IpVersion(values) => values.clone(),
        Leaf::DestPort(values) => values.iter().map(u16::to_string).collect(),
        Leaf::DestPortRange(values) => values
            .iter()
            .map(|(from, to)| format!("{from}-{to}"))
            .collect(),
    }
}

/// Пути, домены и адреса — числом: в строке таблицы их всё равно не прочесть.
fn describe_leaf(leaf: &Leaf) -> String {
    match leaf {
        Leaf::ProcessPath(values) | Leaf::ProcessName(values) => {
            format!("приложения: {}", values.len())
        }
        Leaf::ProcessPathGlob(values) => format!("маски путей: {}", values.len()),
        Leaf::Domain(values) => format!("домены: {}", values.len()),
        Leaf::DomainSuffix(values) => format!("домены и поддомены: {}", values.len()),
        Leaf::DomainKeyword(values) => format!("слова в домене: {}", values.len()),
        Leaf::DomainRegex(values) => format!("выражения для домена: {}", values.len()),
        Leaf::DestIp(values) => format!("адреса: {}", values.len()),
        Leaf::DestPort(values) => format!("порты: {}", values.len()),
        Leaf::DestPortRange(values) => format!("диапазоны портов: {}", values.len()),
        Leaf::GeoIp(values) => format!("страны: {}", values.len()),
        Leaf::GeoSite(values) => format!("наборы доменов: {}", values.len()),
        // Слово короче числа.
        Leaf::Network(values) => format!("трафик: {}", values.join(", ")),
        Leaf::IpVersion(values) => format!("версия IP: {}", values.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::rule::RuleConfig;
    use serde_json::json;

    use super::*;

    fn condition(value: serde_json::Value) -> Condition {
        serde_json::from_value(value).expect("условие разбирается")
    }

    #[test]
    fn a_rule_row_says_what_the_rule_does() {
        let rule: RuleConfig = serde_json::from_value(json!({
            "id": "r1",
            "name": "Игры мимо",
            "when": { "process_name": ["steam.exe"] },
            "action": "direct"
        }))
        .expect("правило разбирается");

        assert_eq!(describe_condition(&rule.when), "приложения: 1");
        assert_eq!(
            describe_action(&rule.action),
            crate::i18n::s().action_direct
        );
    }

    #[test]
    fn values_are_counted_not_listed() {
        let apps: Vec<String> = (0..20).map(|index| format!("app{index}.exe")).collect();
        let described = describe_condition(&condition(json!({ "process_name": apps })));

        assert_eq!(described, "приложения: 20");
    }

    #[test]
    fn traffic_kind_is_named() {
        assert_eq!(
            describe_condition(&condition(json!({ "network": ["tcp"] }))),
            "трафик: tcp"
        );
    }

    #[test]
    fn describes_nested_conditions() {
        let described = describe_condition(&condition(json!({
            "all": [
                { "process_name": ["steam.exe"] },
                { "domain_suffix": ["steamcontent.com"] }
            ]
        })));
        assert_eq!(described, "приложения: 1, домены и поддомены: 1");
    }

    #[test]
    fn actions_are_told_apart() {
        let labels = [
            describe_action(&RuleAction::Direct),
            describe_action(&RuleAction::Block),
            describe_action(&RuleAction::Tunnel { profile: None }),
        ];
        let unique: std::collections::HashSet<&String> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len());
    }

    #[test]
    fn a_tunnel_with_a_profile_names_it() {
        let label = describe_action(&RuleAction::Tunnel {
            profile: Some("office".to_owned()),
        });
        assert!(label.contains("office"));
    }

    #[test]
    fn every_leaf_kind_is_described() {
        let leaves = [
            json!({ "process_path": ["c:/app.exe"] }),
            json!({ "process_name": ["app.exe"] }),
            json!({ "process_path_glob": ["c:/**/*.exe"] }),
            json!({ "domain": ["example.com"] }),
            json!({ "domain_suffix": ["example.com"] }),
            json!({ "domain_keyword": ["example"] }),
            json!({ "domain_regex": ["^ads"] }),
            json!({ "dest_ip": ["10.0.0.0/8"] }),
            json!({ "dest_port": [443] }),
            json!({ "dest_port_range": [[8000, 8100]] }),
            json!({ "geo_ip": ["RU"] }),
            json!({ "geo_site": ["ads"] }),
            json!({ "network": ["tcp"] }),
            json!({ "ip_version": ["v4"] }),
        ];

        for leaf in leaves {
            let described = describe_condition(&condition(leaf.clone()));
            assert!(!described.is_empty(), "нет описания для {leaf}");
            assert!(described.contains(':'), "описание без подписи: {described}");
        }
    }
}
