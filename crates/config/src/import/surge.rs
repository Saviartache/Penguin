//! Список Surge и Shadowrocket: раздел `[Rule]`, строка `ТИП,значение,действие`.
//!
//! Подряд идущие строки с одним действием под одним заголовком-комментарием
//! становятся одной группой: порядок проверки от этого не меняется — любое
//! совпадение внутри них даёт одно и то же действие. По той же причине группа
//! делится на две: то, что открывает форма (домены с поддоменами и подсети), и
//! остальное.
//!
//! Чего набор не умеет (`IP-ASN`, `USER-AGENT`, `GEOIP` без базы, `AND`), не
//! угадывается, а возвращается списком пропущенного.

use std::net::IpAddr;

use crate::schema::routing::TunnelMode;
use crate::schema::rule::{Condition, Leaf, RuleAction, RuleConfig};

/// Разобранный список.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Imported {
    /// Группы по порядку; `id` пуст — его выдаёт тот, кто знает весь набор.
    pub rules: Vec<RuleConfig>,
    /// Куда идёт всё остальное (`FINAL`), если сказано.
    pub mode: Option<TunnelMode>,
    /// Строки, которые набор не выразит, — как в файле.
    pub skipped: Vec<String>,
}

/// Группа в сборке: заголовок и действие общие, листья копятся.
struct Group {
    block: usize,
    name: String,
    action: RuleAction,
    leaves: Vec<Leaf>,
}

/// Разбирает текст списка. Файл с разделами читается только в `[Rule]`, без
/// разделов — целиком (так выглядят отдельные `.list`).
pub fn parse_surge(text: &str) -> Imported {
    let mut imported = Imported::default();
    let mut groups: Vec<Group> = Vec::new();
    let mut in_rules = !text.lines().any(|line| is_section(line.trim()));
    let mut heading = String::new();
    // Номер заголовка: группа не переходит через новый.
    let mut block = 0;

    for line in text.lines().map(str::trim) {
        if is_section(line) {
            in_rules = line.eq_ignore_ascii_case("[Rule]");
            heading.clear();
            block += 1;
            continue;
        }
        if !in_rules || line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#').or_else(|| line.strip_prefix("//")) {
            if let Some(title) = title(comment) {
                heading = title.to_owned();
                block += 1;
            }
            continue;
        }

        match entry(line) {
            Some(Entry::Final(mode)) => imported.mode = Some(mode),
            Some(Entry::Rule(leaf, action)) => add(&mut groups, block, &heading, leaf, action),
            None => imported.skipped.push(line.to_owned()),
        }
    }

    imported.rules = groups.into_iter().flat_map(split).collect();
    imported
}

enum Entry {
    Final(TunnelMode),
    Rule(Leaf, RuleAction),
}

fn is_section(line: &str) -> bool {
    line.starts_with('[') && line.ends_with(']')
}

/// Заголовок группы; закомментированное правило и ссылка заголовком не считаются.
pub(crate) fn title(comment: &str) -> Option<&str> {
    let comment = comment.trim();
    let first = comment.split(',').next().unwrap_or_default();
    let is_rule = comment.contains(',')
        && first
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-');
    let is_link = comment.starts_with("http://") || comment.starts_with("https://");
    (!comment.is_empty() && !is_rule && !is_link).then_some(comment)
}

fn entry(line: &str) -> Option<Entry> {
    let fields: Vec<&str> = line.split(',').map(str::trim).collect();
    match fields.as_slice() {
        [kind, policy, ..] if is_final(kind) => Some(Entry::Final(mode_of(policy))),
        [kind, value, policy, ..] => Some(Entry::Rule(leaf(kind, value)?, action_of(policy))),
        _ => None,
    }
}

fn is_final(kind: &str) -> bool {
    kind.eq_ignore_ascii_case("FINAL") || kind.eq_ignore_ascii_case("MATCH")
}

/// Лист набора; `None` — тип не поддерживается или значение неверно.
fn leaf(kind: &str, value: &str) -> Option<Leaf> {
    if value.is_empty() {
        return None;
    }
    let one = || vec![value.to_owned()];
    let domain = || vec![value.to_ascii_lowercase()];

    match kind.to_ascii_uppercase().as_str() {
        "DOMAIN" => Some(Leaf::Domain(domain())),
        "DOMAIN-SUFFIX" => Some(Leaf::DomainSuffix(domain())),
        "DOMAIN-KEYWORD" => Some(Leaf::DomainKeyword(domain())),
        "IP-CIDR" | "IP-CIDR6" if is_network(value) => Some(Leaf::DestIp(one())),
        "DST-PORT" | "DEST-PORT" => value.parse().ok().map(|port| Leaf::DestPort(vec![port])),
        "PROCESS-NAME" => Some(Leaf::ProcessName(one())),
        _ => None,
    }
}

/// Адрес или подсеть: неверная подсеть сломала бы сборку всего набора.
fn is_network(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return value.parse::<IpAddr>().is_ok();
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let longest = if address.is_ipv4() { 32 } else { 128 };
    prefix.parse::<u8>().is_ok_and(|bits| bits <= longest)
}

/// Действие по имени политики; любое имя, кроме прямого и отказов, — сервер.
fn action_of(policy: &str) -> RuleAction {
    match mode_of(policy) {
        TunnelMode::Direct => RuleAction::Direct,
        TunnelMode::Block => RuleAction::Block,
        TunnelMode::Tunnel => RuleAction::Tunnel { profile: None },
    }
}

fn mode_of(policy: &str) -> TunnelMode {
    let policy = policy.to_ascii_uppercase();
    if policy == "DIRECT" {
        TunnelMode::Direct
    } else if policy.starts_with("REJECT") {
        TunnelMode::Block
    } else {
        TunnelMode::Tunnel
    }
}

fn add(groups: &mut Vec<Group>, block: usize, name: &str, leaf: Leaf, action: RuleAction) {
    match groups.last_mut() {
        Some(last) if last.block == block && last.action == action => merge(&mut last.leaves, leaf),
        _ => groups.push(Group {
            block,
            name: name.to_owned(),
            action,
            leaves: vec![leaf],
        }),
    }
}

/// Дописывает значения к листу того же вида; иначе — новый лист.
fn merge(leaves: &mut Vec<Leaf>, leaf: Leaf) {
    for known in leaves.iter_mut() {
        match (known, &leaf) {
            (Leaf::Domain(to), Leaf::Domain(from))
            | (Leaf::DomainSuffix(to), Leaf::DomainSuffix(from))
            | (Leaf::DomainKeyword(to), Leaf::DomainKeyword(from))
            | (Leaf::DestIp(to), Leaf::DestIp(from))
            | (Leaf::ProcessName(to), Leaf::ProcessName(from)) => {
                to.extend(from.iter().cloned());
                return;
            }
            (Leaf::DestPort(to), Leaf::DestPort(from)) => {
                to.extend(from);
                return;
            }
            _ => {}
        }
    }
    leaves.push(leaf);
}

/// Группа — в одно-два правила: открываемое формой и остальное.
fn split(group: Group) -> Vec<RuleConfig> {
    let (form, rest): (Vec<Leaf>, Vec<Leaf>) = group
        .leaves
        .into_iter()
        .partition(|leaf| matches!(leaf, Leaf::DomainSuffix(_) | Leaf::DestIp(_)));

    [form, rest]
        .into_iter()
        .filter(|leaves| !leaves.is_empty())
        .map(|leaves| RuleConfig {
            id: String::new(),
            name: group.name.clone(),
            enabled: true,
            priority: 0,
            when: any_of(leaves),
            action: group.action.clone(),
        })
        .collect()
}

fn any_of(mut leaves: Vec<Leaf>) -> Condition {
    if leaves.len() == 1 {
        return Condition::Leaf(leaves.remove(0));
    }
    Condition::Any {
        any: leaves.into_iter().map(Condition::Leaf).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Выдержка из списка, выгруженного Shadowrocket.
    const SAMPLE: &str = "\
# Shadowrocket: 2026-10-16 11:56:52
[General]
skip-proxy = 192.168.0.0/16, localhost
# DOMAIN-SUFFIX,general.example,DIRECT

[Rule]
DOMAIN-SUFFIX,gosuslugi.ru,DIRECT
# Block HTTP3/QUIC
# AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP

# Apple IPv6 Blocks
IP-CIDR,2620:149::/32,DIRECT,no-resolve
IP-CIDR,2A01:B740::/32,DIRECT,no-resolve

# Apple Intelligence, Siri
# https://support.apple.com/en-us/101555
DOMAIN-SUFFIX,apple-relay.apple.com,PROXY
DOMAIN,copilot.microsoft.com,PROXY
DOMAIN-SUFFIX,Apple-Relay.Cloudflare.com,PROXY
IP-ASN,132203,DIRECT,no-resolve
USER-AGENT,Line*,PROXY
DOMAIN-KEYWORD,google,REJECT
IP-CIDR,10.0.0.0/99,DIRECT
GEOIP,CN,DIRECT
FINAL,DIRECT

[Host]
localhost = 127.0.0.1
";

    fn names(imported: &Imported) -> Vec<&str> {
        imported
            .rules
            .iter()
            .map(|rule| rule.name.as_str())
            .collect()
    }

    #[test]
    fn only_the_rule_section_is_read() {
        let imported = parse_surge(SAMPLE);
        assert!(
            imported
                .rules
                .iter()
                .all(|rule| !format!("{rule:?}").contains("general.example"))
        );
        assert!(!imported.skipped.iter().any(|line| line.contains('=')));
    }

    #[test]
    fn rules_are_grouped_by_heading_and_action() {
        let imported = parse_surge(SAMPLE);
        assert_eq!(
            names(&imported),
            [
                "",
                "Apple IPv6 Blocks",
                "Apple Intelligence, Siri",
                "Apple Intelligence, Siri",
                "Apple Intelligence, Siri",
            ]
        );
        assert_eq!(
            imported.rules[1].when,
            Condition::Leaf(Leaf::DestIp(vec![
                "2620:149::/32".to_owned(),
                "2A01:B740::/32".to_owned()
            ]))
        );
    }

    #[test]
    fn a_group_splits_into_what_the_form_opens_and_the_rest() {
        let imported = parse_surge(SAMPLE);
        let tunnel = RuleAction::Tunnel { profile: None };

        assert_eq!(imported.rules[2].action, tunnel);
        assert_eq!(
            imported.rules[2].when,
            Condition::Leaf(Leaf::DomainSuffix(vec![
                "apple-relay.apple.com".to_owned(),
                "apple-relay.cloudflare.com".to_owned()
            ]))
        );
        assert_eq!(imported.rules[3].action, tunnel);
        assert_eq!(
            imported.rules[3].when,
            Condition::Leaf(Leaf::Domain(vec!["copilot.microsoft.com".to_owned()]))
        );
        assert_eq!(imported.rules[4].action, RuleAction::Block);
    }

    #[test]
    fn final_becomes_the_mode() {
        assert_eq!(parse_surge(SAMPLE).mode, Some(TunnelMode::Direct));
        assert_eq!(parse_surge("FINAL,Proxy").mode, Some(TunnelMode::Tunnel));
    }

    #[test]
    fn what_the_set_cannot_express_is_returned() {
        assert_eq!(
            parse_surge(SAMPLE).skipped,
            [
                "IP-ASN,132203,DIRECT,no-resolve",
                "USER-AGENT,Line*,PROXY",
                "IP-CIDR,10.0.0.0/99,DIRECT",
                "GEOIP,CN,DIRECT",
            ]
        );
    }

    #[test]
    fn a_list_without_sections_is_read_whole() {
        let imported = parse_surge("DOMAIN-SUFFIX,example.com,REJECT-TINYGIF\nDST-PORT,443,DIRECT");
        assert_eq!(imported.rules.len(), 2);
        assert_eq!(imported.rules[0].action, RuleAction::Block);
        assert_eq!(
            imported.rules[1].when,
            Condition::Leaf(Leaf::DestPort(vec![443]))
        );
    }

    #[test]
    fn a_rule_without_a_policy_is_skipped() {
        assert_eq!(
            parse_surge("DOMAIN-SUFFIX,example.com").skipped,
            ["DOMAIN-SUFFIX,example.com"]
        );
    }
}
