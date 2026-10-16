//! Набор правил — в список Surge, который читает [`crate::import::parse_surge`].
//!
//! Группа — заголовок-комментарий и строки под ним: так импорт вернёт её
//! отдельной группой с тем же именем. Выключенная группа выгружается
//! закомментированной: импорт её пропустит, но и не включит.
//!
//! Surge не выражает `all`, `not` и листья вроде пути процесса или GeoIP; такое
//! не угадывается, а называется в [`Exported::skipped`].

use std::fmt::Write;

use crate::import::title;
use crate::schema::routing::TunnelMode;
use crate::schema::rule::{Condition, Leaf, RuleAction, RuleConfig};

/// Выгруженный список.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Exported {
    /// Текст файла.
    pub text: String,
    /// Сколько групп записано.
    pub written: usize,
    /// Имена групп, потерявших условия целиком или частично.
    pub skipped: Vec<String>,
}

/// Собирает список в порядке проверки и «всё остальное» строкой `FINAL`.
pub fn to_surge(rules: &[RuleConfig], mode: TunnelMode) -> Exported {
    let mut ordered: Vec<&RuleConfig> = rules.iter().collect();
    // Как у маршрутизатора: устойчиво, по приоритету.
    ordered.sort_by_key(|rule| rule.priority);

    let mut exported = Exported {
        text: "[Rule]\n".to_owned(),
        ..Exported::default()
    };
    for rule in ordered {
        let (lines, lossy) = lines(rule);
        if lossy {
            exported.skipped.push(rule.name.clone());
        }
        if lines.is_empty() {
            continue;
        }
        exported.written += 1;
        let _ = writeln!(exported.text, "\n# {}", heading(rule));
        let mark = if rule.enabled { "" } else { "# " };
        for line in lines {
            let _ = writeln!(exported.text, "{mark}{line}");
        }
    }
    let _ = writeln!(exported.text, "\nFINAL,{}", policy_of_mode(mode));
    exported
}

/// Заголовок, который импорт примет за заголовок; иначе группа слилась бы с
/// соседней.
fn heading(rule: &RuleConfig) -> String {
    let name = rule.name.split_whitespace().collect::<Vec<_>>().join(" ");
    if title(&name).is_some() {
        name
    } else {
        rule.id.clone()
    }
}

/// Строки группы и признак потери.
fn lines(rule: &RuleConfig) -> (Vec<String>, bool) {
    let Some(leaves) = leaves(&rule.when) else {
        return (Vec::new(), true);
    };
    let policy = policy(&rule.action);
    let mut lossy = false;
    let mut lines = Vec::new();
    for leaf in leaves {
        let Some(entries) = entries(leaf) else {
            lossy = true;
            continue;
        };
        for (kind, value) in entries {
            // Запятая разорвала бы строку на поля.
            if value.contains(',') {
                lossy = true;
                continue;
            }
            lines.push(format!("{kind},{value},{policy}"));
        }
    }
    (lines, lossy)
}

/// Листья условия-«или»; `None` — в дереве есть `all` или `not`.
fn leaves(condition: &Condition) -> Option<Vec<&Leaf>> {
    match condition {
        Condition::Leaf(leaf) => Some(vec![leaf]),
        Condition::Any { any } => any.iter().try_fold(Vec::new(), |mut all, child| {
            all.extend(leaves(child)?);
            Some(all)
        }),
        Condition::All { .. } | Condition::Not { .. } => None,
    }
}

/// Пары «тип строки, значение» листа; `None` — Surge его не выражает.
fn entries(leaf: &Leaf) -> Option<Vec<(&'static str, String)>> {
    let (kind, values) = match leaf {
        Leaf::Domain(values) => ("DOMAIN", values),
        Leaf::DomainSuffix(values) => ("DOMAIN-SUFFIX", values),
        Leaf::DomainKeyword(values) => ("DOMAIN-KEYWORD", values),
        Leaf::ProcessName(values) => ("PROCESS-NAME", values),
        Leaf::DestIp(values) => {
            return Some(
                values
                    .iter()
                    .map(|value| (ip_kind(value), value.clone()))
                    .collect(),
            );
        }
        Leaf::DestPort(ports) => {
            return Some(
                ports
                    .iter()
                    .map(|port| ("DST-PORT", port.to_string()))
                    .collect(),
            );
        }
        _ => return None,
    };
    Some(values.iter().map(|value| (kind, value.clone())).collect())
}

fn ip_kind(value: &str) -> &'static str {
    if value.contains(':') {
        "IP-CIDR6"
    } else {
        "IP-CIDR"
    }
}

fn policy(action: &RuleAction) -> &'static str {
    match action {
        // Профиль не переносится: импорт любое имя политики ведёт в активный.
        RuleAction::Tunnel { .. } => "PROXY",
        RuleAction::Direct => "DIRECT",
        RuleAction::Block => "REJECT",
    }
}

fn policy_of_mode(mode: TunnelMode) -> &'static str {
    match mode {
        TunnelMode::Tunnel => "PROXY",
        TunnelMode::Direct => "DIRECT",
        TunnelMode::Block => "REJECT",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::import::parse_surge;

    fn rules(value: serde_json::Value) -> Vec<RuleConfig> {
        serde_json::from_value(value).expect("правила разбираются")
    }

    /// Круговой прогон: внешнего вектора у собственной выгрузки нет.
    #[test]
    fn import_reads_back_what_export_wrote() {
        let set = rules(json!([
            { "id": "r1", "name": "Госуслуги", "when": { "domain_suffix": ["gosuslugi.ru"] }, "action": "direct" },
            { "id": "r2", "name": "Apple IPv6", "when": { "dest_ip": ["2620:149::/32", "17.0.0.0/8"] }, "action": "direct" },
            { "id": "r3", "name": "Copilot", "when": { "domain": ["copilot.microsoft.com"] }, "action": "tunnel" },
            { "id": "r4", "name": "Порт", "when": { "dest_port": [443] }, "action": "block" }
        ]));
        let exported = to_surge(&set, TunnelMode::Direct);
        let imported = parse_surge(&exported.text);

        assert!(imported.skipped.is_empty(), "{:?}", imported.skipped);
        assert!(exported.skipped.is_empty());
        assert_eq!(exported.written, 4);
        assert_eq!(imported.mode, Some(TunnelMode::Direct));
        let back: Vec<_> = imported
            .rules
            .iter()
            .map(|rule| (rule.name.as_str(), &rule.when, &rule.action))
            .collect();
        let sent: Vec<_> = set
            .iter()
            .map(|rule| (rule.name.as_str(), &rule.when, &rule.action))
            .collect();
        assert_eq!(back, sent);
    }

    #[test]
    fn neighbours_with_one_action_stay_apart() {
        let set = rules(json!([
            { "id": "r1", "name": "А", "when": { "domain": ["a.example"] }, "action": "direct" },
            { "id": "r2", "name": "", "when": { "domain": ["b.example"] }, "action": "direct" }
        ]));
        let imported = parse_surge(&to_surge(&set, TunnelMode::Tunnel).text);
        let names: Vec<_> = imported.rules.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["А", "r2"]);
    }

    #[test]
    fn the_order_follows_priority() {
        let set = rules(json!([
            { "id": "r1", "name": "Второе", "priority": 10, "when": { "domain": ["a.example"] }, "action": "direct" },
            { "id": "r2", "name": "Первое", "priority": -10, "when": { "domain": ["b.example"] }, "action": "block" }
        ]));
        let imported = parse_surge(&to_surge(&set, TunnelMode::Tunnel).text);
        assert_eq!(imported.rules[0].name, "Первое");
    }

    #[test]
    fn a_disabled_group_is_written_but_not_imported() {
        let set = rules(json!([
            { "id": "r1", "name": "Выкл", "enabled": false, "when": { "domain": ["a.example"] }, "action": "direct" }
        ]));
        let exported = to_surge(&set, TunnelMode::Tunnel);
        assert!(exported.text.contains("# DOMAIN,a.example,DIRECT"));
        assert!(parse_surge(&exported.text).rules.is_empty());
    }

    #[test]
    fn what_surge_cannot_express_is_named() {
        let set = rules(json!([
            { "id": "r1", "name": "И", "when": { "all": [{ "domain": ["a.example"] }, { "dest_port": [443] }] }, "action": "direct" },
            { "id": "r2", "name": "Часть", "when": { "any": [{ "domain": ["b.example"] }, { "geo_ip": ["RU"] }] }, "action": "direct" }
        ]));
        let exported = to_surge(&set, TunnelMode::Tunnel);
        assert_eq!(exported.skipped, ["И", "Часть"]);
        assert_eq!(exported.written, 1);
        assert!(exported.text.contains("DOMAIN,b.example,DIRECT"));
    }
}
