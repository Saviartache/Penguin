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
        Condition::All { all } => join(all, " и "),
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

/// Список значений, обрезанный до читаемой длины.
fn short(values: &[String]) -> String {
    const SHOWN: usize = 3;

    if values.len() <= SHOWN {
        return values.join(", ");
    }
    format!(
        "{}, ещё {}",
        values[..SHOWN].join(", "),
        values.len() - SHOWN
    )
}

fn short_ports(values: &[u16]) -> String {
    short(&values.iter().map(u16::to_string).collect::<Vec<_>>())
}

fn describe_leaf(leaf: &Leaf) -> String {
    match leaf {
        Leaf::ProcessPath(values) => format!("путь: {}", short(values)),
        Leaf::ProcessName(values) => format!("приложение: {}", short(values)),
        Leaf::ProcessPathGlob(values) => format!("путь по маске: {}", short(values)),
        Leaf::Domain(values) => format!("домен: {}", short(values)),
        Leaf::DomainSuffix(values) => format!("домен и поддомены: {}", short(values)),
        Leaf::DomainKeyword(values) => format!("домен содержит: {}", short(values)),
        Leaf::DomainRegex(values) => format!("домен по выражению: {}", short(values)),
        Leaf::DestIp(values) => format!("адрес: {}", short(values)),
        Leaf::DestPort(values) => format!("порт: {}", short_ports(values)),
        Leaf::DestPortRange(values) => {
            let ranges: Vec<String> = values
                .iter()
                .map(|(from, to)| format!("{from}-{to}"))
                .collect();
            format!("порты: {}", short(&ranges))
        }
        Leaf::GeoIp(values) => format!("страна: {}", short(values)),
        Leaf::GeoSite(values) => format!("набор доменов: {}", short(values)),
        Leaf::Network(values) => format!("трафик: {}", short(values)),
        Leaf::IpVersion(values) => format!("версия IP: {}", short(values)),
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

        assert_eq!(describe_condition(&rule.when), "приложение: steam.exe");
        assert_eq!(
            describe_action(&rule.action),
            crate::i18n::s().action_direct
        );
    }

    #[test]
    fn describes_a_simple_leaf() {
        assert_eq!(
            describe_condition(&condition(json!({ "process_name": ["steam.exe"] }))),
            "приложение: steam.exe"
        );
    }

    #[test]
    fn shortens_long_lists() {
        let apps: Vec<String> = (0..20).map(|index| format!("app{index}.exe")).collect();
        let described = describe_condition(&condition(json!({ "process_name": apps })));

        assert!(
            described.contains("ещё 17"),
            "список не обрезан: {described}"
        );
        assert!(described.len() < 80, "строка всё ещё длинная: {described}");
    }

    #[test]
    fn describes_nested_conditions() {
        let described = describe_condition(&condition(json!({
            "all": [
                { "process_name": ["steam.exe"] },
                { "domain_suffix": ["steamcontent.com"] }
            ]
        })));
        assert!(described.contains(" и "));
        assert!(described.contains("steam.exe"));
        assert!(described.contains("steamcontent.com"));
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
