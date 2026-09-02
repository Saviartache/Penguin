//! Набор правил и порядок их применения.

pub mod compile;
pub mod order;
pub mod rule;

use penguin_config::schema::routing::RoutingConfig;
use penguin_match::target::MatchTarget;

pub use self::compile::CompileContext;
pub use self::rule::Rule;
use crate::error::RouterResult;

/// Готовый к применению набор правил.
#[derive(Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl std::fmt::Debug for RuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSet")
            .field("rules", &self.rules.len())
            .finish()
    }
}

impl RuleSet {
    /// Пустой набор.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Собирает набор из конфигурации.
    ///
    /// Выключенные правила отбрасываются здесь, а не проверяются на каждом
    /// соединении: выключенное правило не должно стоить ничего.
    pub fn compile(config: &RoutingConfig, ctx: &CompileContext) -> RouterResult<Self> {
        let mut rules = config
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .map(|rule| compile::compile_rule(rule, ctx))
            .collect::<RouterResult<Vec<_>>>()?;

        order::sort(&mut rules);
        Ok(Self { rules })
    }

    /// Первое подходящее правило.
    pub fn first_match(&self, target: &MatchTarget<'_>) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.matches(target))
    }

    /// Все подходящие правила по порядку.
    ///
    /// Нужно экрану проверки: пользователю важно видеть не только сработавшее
    /// правило, но и те, что сработали бы, не будь его.
    pub fn all_matches(&self, target: &MatchTarget<'_>) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|rule| rule.matches(target))
            .collect()
    }

    /// Сколько правил в наборе.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Набор пуст.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Правила по порядку разбора.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::rule::RuleConfig;
    use serde_json::json;

    use super::*;
    use crate::decision::Decision;

    fn routing(rules: serde_json::Value) -> RoutingConfig {
        let rules: Vec<RuleConfig> = serde_json::from_value(rules).expect("правила разбираются");
        RoutingConfig {
            rules,
            ..RoutingConfig::default()
        }
    }

    fn target() -> MatchTarget<'static> {
        use std::net::SocketAddr;

        use penguin_core::network::Network;

        let destination: SocketAddr = "1.2.3.4:443".parse().expect("адрес");
        MatchTarget::to_address(Network::Tcp, destination)
            .with_domain("example.com")
            .with_process("c:/apps/app.exe", "app.exe")
    }

    #[test]
    fn disabled_rules_are_dropped_at_compile_time() {
        let config = routing(json!([
            { "id": "выключено", "enabled": false, "when": { "dest_port": [443] }, "action": "direct" },
            { "id": "включено", "when": { "dest_port": [443] }, "action": "block" }
        ]));
        let set = RuleSet::compile(&config, &CompileContext::default()).expect("собирается");
        assert_eq!(set.len(), 1);
        assert_eq!(set.rules()[0].id.as_str(), "включено");
    }

    #[test]
    fn first_match_wins() {
        let config = routing(json!([
            { "id": "второе", "priority": 10, "when": { "dest_port": [443] }, "action": "block" },
            { "id": "первое", "priority": -10, "when": { "dest_port": [443] }, "action": "direct" }
        ]));
        let set = RuleSet::compile(&config, &CompileContext::default()).expect("собирается");
        let matched = set.first_match(&target()).expect("совпало");
        assert_eq!(matched.id.as_str(), "первое");
        assert_eq!(matched.action, Decision::Direct);
    }

    #[test]
    fn all_matches_lists_the_alternatives() {
        // Экран проверки показывает не только сработавшее правило, но и те,
        // что сработали бы без него.
        let config = routing(json!([
            { "id": "по-порту", "when": { "dest_port": [443] }, "action": "direct" },
            { "id": "по-домену", "when": { "domain_suffix": ["example.com"] }, "action": "block" },
            { "id": "мимо", "when": { "dest_port": [80] }, "action": "block" }
        ]));
        let set = RuleSet::compile(&config, &CompileContext::default()).expect("собирается");
        let ids: Vec<&str> = set
            .all_matches(&target())
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(ids, vec!["по-порту", "по-домену"]);
    }

    #[test]
    fn broken_rule_fails_the_whole_set() {
        // Собрать половину правил и молча выбросить остальные — худший исход:
        // трафик пойдёт не туда, а пользователь об этом не узнает.
        let config = routing(json!([
            { "id": "хорошее", "when": { "dest_port": [443] }, "action": "direct" },
            { "id": "плохое", "when": { "dest_ip": ["не адрес"] }, "action": "block" }
        ]));
        assert!(RuleSet::compile(&config, &CompileContext::default()).is_err());
    }

    #[test]
    fn empty_config_gives_an_empty_set() {
        let set = RuleSet::compile(&RoutingConfig::default(), &CompileContext::default())
            .expect("собирается");
        assert!(set.is_empty());
        assert!(set.first_match(&target()).is_none());
    }
}
