//! Трассировка решения: какое правило сработало и почему. То же самое видит
//! пользователь в GUI.
//!
//! Без этого набор из тридцати правил — чёрный ящик, и единственный способ
//! понять, почему трафик пошёл не туда, — выключать правила по одному.
//!
//! Экран проверки принимает приложение и адрес и показывает не только
//! сработавшее правило, но и те, что сработали бы без него: чаще всего
//! неожиданный исход объясняется правилом, стоящим выше по порядку.

use serde::{Deserialize, Serialize};

use crate::context::FlowContext;
use crate::engine::{Router, default_decision};

/// Разбор одного правила при проверке.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleTrace {
    /// Идентификатор правила.
    pub id: String,
    /// Имя правила.
    pub name: String,
    /// Условие, записанное словами.
    pub condition: String,
    /// Подошло ли.
    pub matched: bool,
    /// Это правило и дало решение.
    pub decisive: bool,
}

/// Результат проверки.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    /// Что получилось.
    pub decision: String,
    /// Отчего.
    pub reason: String,
    /// Все правила по порядку разбора.
    pub rules: Vec<RuleTrace>,
}

/// Объясняет, что случится с таким соединением.
///
/// Кэш при этом не трогается ни на чтение, ни на запись: проверка — это
/// вопрос «что было бы», а не настоящее соединение, и засорять им кэш
/// решений нельзя.
pub fn explain(router: &Router, flow: &FlowContext) -> Explanation {
    let verdict = router.evaluate(flow);
    let target = flow.as_match_target();
    let active = router.active();

    // Сработавшее правило — первое подошедшее; остальные подошедшие
    // показываются как «сработало бы, не будь предыдущего».
    let mut decisive_found = false;
    let mut rules = Vec::new();

    for rule in router.rule_set().rules() {
        let matched = rule.matches(&target);
        let decisive = matched && !decisive_found;
        if decisive {
            decisive_found = true;
        }
        rules.push(RuleTrace {
            id: rule.id.to_string(),
            name: rule.name.clone(),
            condition: rule.condition.describe(),
            matched,
            decisive,
        });
    }

    let fallback = default_decision(router.mode(), &active);
    let reason = if decisive_found {
        verdict.reason.to_string()
    } else {
        format!("{} (режим `{}`)", verdict.reason, router.mode().as_str())
    };
    let _ = fallback;

    Explanation {
        decision: verdict.decision.to_string(),
        reason,
        rules,
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use penguin_config::schema::routing::{RoutingConfig, TunnelMode};
    use penguin_config::schema::rule::RuleConfig;
    use penguin_core::id::OutboundId;
    use penguin_core::network::Network;
    use penguin_process::identity::ProcessIdentity;
    use serde_json::json;

    use super::*;
    use crate::ruleset::CompileContext;

    fn router(rules: serde_json::Value) -> Router {
        let rules: Vec<RuleConfig> = serde_json::from_value(rules).expect("правила разбираются");
        let config = RoutingConfig {
            mode: TunnelMode::Full,
            rules,
            ..RoutingConfig::default()
        };
        Router::new(&config, OutboundId::new("home"), &CompileContext::default())
            .expect("собирается")
    }

    fn flow(destination: &str, process: Option<&str>) -> FlowContext {
        let destination: SocketAddr = destination.parse().expect("адрес");
        let mut flow = FlowContext::to_address(
            Network::Tcp,
            "127.0.0.1:50000".parse().expect("адрес"),
            destination,
        );
        if let Some(path) = process {
            flow = flow.with_process(ProcessIdentity::new(1, path));
        }
        flow
    }

    #[test]
    fn names_the_decisive_rule() {
        let router = router(json!([
            { "id": "лан", "priority": -10, "name": "Локальная сеть", "when": { "dest_ip": ["10.0.0.0/8"] }, "action": "direct" },
            { "id": "всё", "name": "Всё остальное", "when": { "dest_ip": ["0.0.0.0/0"] }, "action": "block" }
        ]));

        let explanation = explain(&router, &flow("10.1.2.3:443", None));
        assert_eq!(explanation.decision, "direct");
        assert_eq!(explanation.reason, "правило «Локальная сеть»");

        // Оба правила подошли, но решающим было первое — и это видно.
        let matched: Vec<&RuleTrace> = explanation.rules.iter().filter(|r| r.matched).collect();
        assert_eq!(matched.len(), 2);
        assert!(matched[0].decisive);
        assert!(
            !matched[1].decisive,
            "решающим может быть только одно правило"
        );
    }

    #[test]
    fn shows_the_condition_in_words() {
        let router = router(json!([
            { "id": "r1", "when": { "process_name": ["chrome.exe"] }, "action": "direct" }
        ]));
        let explanation = explain(&router, &flow("1.2.3.4:443", Some("c:/chrome.exe")));
        assert!(explanation.rules[0].condition.contains("chrome.exe"));
    }

    #[test]
    fn explains_the_mode_when_nothing_matched() {
        let router = router(json!([
            { "id": "r1", "when": { "dest_port": [80] }, "action": "block" }
        ]));
        let explanation = explain(&router, &flow("1.2.3.4:443", None));
        assert_eq!(explanation.decision, "proxy[home]");
        assert!(
            explanation.reason.contains("full"),
            "режим не назван: {}",
            explanation.reason
        );
        assert!(!explanation.rules[0].matched);
    }

    #[test]
    fn explaining_does_not_pollute_the_cache() {
        // Проверка — вопрос «что было бы», а не настоящее соединение.
        let router = router(json!([]));
        explain(&router, &flow("1.2.3.4:443", None));
        assert!(router.cache_is_empty());
    }
}
