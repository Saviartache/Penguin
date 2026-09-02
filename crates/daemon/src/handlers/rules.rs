//! Правила: чтение, изменение, проверка на пробном соединении.

use std::net::SocketAddr;
use std::sync::Arc;

use penguin_core::address::SocketAddress;
use penguin_core::network::Network;
use penguin_engine::Engine;
use penguin_ipc::schema::{Explanation, Response, RuleTrace};
use penguin_process::identity::ProcessIdentity;
use penguin_router::context::FlowContext;

/// Объясняет, что случится с таким соединением.
///
/// Настоящего соединения не открывается: разбирается тот же набор правил тем
/// же кодом, что и на горячем пути, просто по выдуманному соединению.
pub fn explain(
    engine: &Arc<Engine>,
    destination: &str,
    process: Option<&str>,
    udp: bool,
) -> Response {
    let Ok(target) = destination.parse::<SocketAddress>() else {
        return Response::error(format!("не разбирается адрес `{destination}`"), true);
    };

    let network = if udp { Network::Udp } else { Network::Tcp };
    // Источник в правилах не участвует; подставляется что угодно осмысленное.
    let source = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut flow = FlowContext::to_target(network, source, target);

    if let Some(path) = process {
        // Пользователь пишет и полный путь, и просто имя файла: личность
        // строится из того, что дали — имя выведется из пути само.
        flow = flow.with_process(ProcessIdentity::new(0, path));
    }

    let inner = penguin_router::explain::explain(engine.router(), &flow);

    Response::Explanation(Box::new(Explanation {
        decision: inner.decision,
        reason: inner.reason,
        rules: inner
            .rules
            .into_iter()
            .map(|rule| RuleTrace {
                id: rule.id,
                name: rule.name,
                condition: rule.condition,
                matched: rule.matched,
                decisive: rule.decisive,
            })
            .collect(),
    }))
}

#[cfg(test)]
mod tests {
    use penguin_config::RootConfig;
    use serde_json::json;

    use super::*;

    fn engine_with_rules(rules: serde_json::Value) -> Arc<Engine> {
        let mut config = RootConfig::default();
        config.routing.rules = serde_json::from_value(rules).expect("правила разбираются");
        Engine::new(config).expect("движок собирается")
    }

    #[test]
    fn explains_a_matching_rule() {
        let engine = engine_with_rules(json!([
            { "id": "игры", "name": "Игры мимо", "when": { "process_name": ["steam.exe"] }, "action": "direct" }
        ]));

        let Response::Explanation(explanation) = explain(
            &engine,
            "example.com:443",
            Some("c:/steam/steam.exe"),
            false,
        ) else {
            panic!("не тот ответ");
        };

        assert_eq!(explanation.decision, "direct");
        assert_eq!(explanation.reason, "правило «Игры мимо»");
        assert!(explanation.rules.iter().any(|rule| rule.decisive));
    }

    #[test]
    fn bad_address_is_reported() {
        let engine = engine_with_rules(json!([]));
        assert!(explain(&engine, "без-порта", None, false).is_error());
    }

    #[test]
    fn udp_flag_reaches_the_router() {
        let engine = engine_with_rules(json!([
            { "id": "udp", "name": "Только UDP", "when": { "network": ["udp"] }, "action": "block" }
        ]));

        let Response::Explanation(over_udp) = explain(&engine, "1.2.3.4:53", None, true) else {
            panic!("не тот ответ");
        };
        assert_eq!(over_udp.decision, "block");

        let Response::Explanation(over_tcp) = explain(&engine, "1.2.3.4:53", None, false) else {
            panic!("не тот ответ");
        };
        assert_ne!(over_tcp.decision, "block");
    }

    #[test]
    fn explaining_does_not_pollute_the_decision_cache() {
        // Проверка — вопрос «что было бы», а не настоящее соединение.
        let engine = engine_with_rules(json!([]));
        explain(&engine, "example.com:443", None, false);
        assert!(engine.router().cache_is_empty());
    }
}
