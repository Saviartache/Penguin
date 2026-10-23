//! Обратный путь: правило из набора — в черновик формы.
//!
//! Форма умеет только «приложения и адреса и порты и вид трафика». Правило,
//! написанное в файле руками (`not`, вложенные `any`, имя процесса), формой не
//! открывается: сохранение молча выбросило бы непонятое.

use penguin_config::schema::rule::{Condition, Leaf, RuleAction, RuleConfig};
use penguin_core::network::Network;

use super::draft::{Action, Draft, Section};

/// Черновик правки; `None` — правило форме не по силам.
pub fn load(index: usize, rule: &RuleConfig) -> Option<Draft> {
    let mut draft = Draft {
        index: Some(index),
        name: rule.name.clone(),
        action: action_of(&rule.action)?,
        ..Draft::default()
    };

    let parts = match &rule.when {
        Condition::All { all } => all.as_slice(),
        single => std::slice::from_ref(single),
    };

    let mut seen = Vec::new();
    for part in parts {
        if let Condition::Leaf(Leaf::Network(names)) = part {
            if draft.network.is_some() {
                return None;
            }
            draft.network = Some(network_of(names)?);
            continue;
        }
        let leaves = leaves_of(part)?;
        let section = section_of(leaves.first()?)?;
        // Два раздела одного вида через «и» форма не покажет.
        if seen.contains(&section) || leaves.iter().any(|leaf| section_of(leaf) != Some(section)) {
            return None;
        }
        seen.push(section);
        leaves.into_iter().for_each(|leaf| absorb(&mut draft, leaf));
    }

    Some(draft)
}

/// Действие формы; тоннель в названный профиль форма не выбирает.
fn action_of(action: &RuleAction) -> Option<Action> {
    match action {
        RuleAction::Tunnel { profile: None } => Some(Action::Tunnel),
        RuleAction::Tunnel { profile: Some(_) } => None,
        RuleAction::Direct => Some(Action::Direct),
        RuleAction::Block => Some(Action::Block),
    }
}

/// Один вид трафика; «TCP или UDP» — это любой, и форма такого не пишет.
fn network_of(names: &[String]) -> Option<Network> {
    match names {
        [name] => name.parse().ok(),
        _ => None,
    }
}

/// Лист или «или» из листьев.
fn leaves_of(condition: &Condition) -> Option<Vec<&Leaf>> {
    match condition {
        Condition::Leaf(leaf) => Some(vec![leaf]),
        Condition::Any { any } => any
            .iter()
            .map(|inner| match inner {
                Condition::Leaf(leaf) => Some(leaf),
                _ => None,
            })
            .collect(),
        Condition::All { .. } | Condition::Not { .. } => None,
    }
}

fn section_of(leaf: &Leaf) -> Option<Section> {
    match leaf {
        Leaf::ProcessPath(_) => Some(Section::Apps),
        Leaf::DomainSuffix(_)
        | Leaf::Domain(_)
        | Leaf::DomainKeyword(_)
        | Leaf::DestIp(_)
        | Leaf::GeoIp(_) => Some(Section::Hosts),
        Leaf::DestPort(_) | Leaf::DestPortRange(_) => Some(Section::Ports),
        _ => None,
    }
}

/// Переносит значения листа в поле его раздела.
fn absorb(draft: &mut Draft, leaf: &Leaf) {
    match leaf {
        Leaf::ProcessPath(paths) => draft.processes.extend(paths.iter().cloned()),
        Leaf::DestIp(values) => draft.hosts.extend(values.iter().cloned()),
        // Пометки вида — те же, что вписывают руками (`host::host_kind`).
        Leaf::DomainSuffix(values) => draft.hosts.extend(values.iter().map(|name| {
            if name.contains('.') {
                name.clone()
            } else {
                format!(".{name}")
            }
        })),
        Leaf::GeoIp(codes) => draft
            .hosts
            .extend(codes.iter().map(|code| code.trim().to_ascii_uppercase())),
        Leaf::Domain(values) => draft
            .hosts
            .extend(values.iter().map(|name| format!("={name}"))),
        Leaf::DomainKeyword(values) => {
            draft
                .hosts
                .extend(values.iter().map(|word| format!("*{word}*")));
        }
        Leaf::DestPort(ports) => draft.ports.extend(ports.iter().map(u16::to_string)),
        Leaf::DestPortRange(ranges) => draft
            .ports
            .extend(ranges.iter().map(|(from, to)| format!("{from}-{to}"))),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rule(value: serde_json::Value) -> RuleConfig {
        serde_json::from_value(value).expect("правило разбирается")
    }

    #[test]
    fn a_built_group_opens_as_it_was_entered() {
        let draft = Draft {
            index: Some(2),
            name: "Видео".to_owned(),
            processes: vec!["c:/chrome.exe".to_owned()],
            hosts: vec!["youtube.com".to_owned(), "10.0.0.0/8".to_owned()],
            ports: vec!["443".to_owned(), "8000-9000".to_owned()],
            network: Some(Network::Tcp),
            action: Action::Direct,
        };
        let built = draft.build("r1").expect("собирается");

        assert_eq!(load(2, &built), Some(draft));
    }

    #[test]
    fn zones_and_countries_open_with_their_marks() {
        let written = rule(json!({
            "id": "r1", "name": "Россия",
            "when": { "any": [
                { "domain_suffix": ["ru", "xn--p1ai"] },
                { "geo_ip": ["ru"] }
            ] },
            "action": "direct"
        }));
        let draft = load(0, &written).expect("форма открывает");
        assert_eq!(draft.hosts, [".ru", ".xn--p1ai", "RU"]);
    }

    #[test]
    fn traffic_both_ways_is_not_opened() {
        let written = rule(json!({
            "id": "r1",
            "when": { "network": ["tcp", "udp"] },
            "action": "direct"
        }));
        assert!(load(0, &written).is_none());
    }

    /// Импорт Surge даёт точные домены и слова — форма открывает их и
    /// сохраняет без расширения до поддоменов.
    #[test]
    fn exact_domains_and_keywords_survive_the_form() {
        let imported = rule(json!({
            "id": "r1", "name": "Copilot",
            "when": { "any": [
                { "domain": ["copilot.microsoft.com"] },
                { "domain_keyword": ["google"] }
            ] },
            "action": "tunnel"
        }));
        let draft = load(0, &imported).expect("форма открывает");
        assert_eq!(draft.hosts, ["=copilot.microsoft.com", "*google*"]);
        assert_eq!(draft.build("r1").expect("собирается"), imported);
    }

    #[test]
    fn a_handwritten_rule_is_not_opened() {
        for when in [
            json!({ "not": { "dest_port": [443] } }),
            json!({ "process_name": ["steam.exe"] }),
            json!({ "all": [{ "dest_port": [80] }, { "dest_port": [443] }] }),
            json!({ "any": [{ "dest_port": [80] }, { "domain_suffix": ["a.com"] }] }),
        ] {
            let rule = rule(json!({ "id": "r1", "when": when, "action": "direct" }));
            assert!(load(0, &rule).is_none(), "открылось: {:?}", rule.when);
        }
    }

    #[test]
    fn a_named_profile_is_not_lost_by_the_form() {
        let rule = rule(json!({
            "id": "r1",
            "when": { "dest_port": [443] },
            "action": { "tunnel": { "profile": "office" } }
        }));
        assert!(load(0, &rule).is_none());
    }
}
