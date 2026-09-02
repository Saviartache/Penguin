//! Просмотр и правка правил, объяснение решения по адресу.
//!
//! `penguin rules explain` отвечает на главный вопрос, который возникает у
//! пользователя с раздельным тоннелированием: **почему это приложение пошло
//! не туда**. Без такой команды остаётся один способ — выключать правила по
//! одному и смотреть, что изменится.
//!
//! Настоящего соединения при этом не открывается: разбирается тот же набор
//! правил тем же кодом, что и на горячем пути, просто по выдуманному
//! соединению.

use anyhow::{Context, Result};
use std::net::SocketAddr;

use penguin_config::RootConfig;
use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;
use penguin_core::network::Network;
use penguin_process::identity::ProcessIdentity;
use penguin_router::context::FlowContext;
use penguin_router::engine::Router;
use penguin_router::explain::{Explanation, explain};
use penguin_router::ruleset::CompileContext;
use serde::Serialize;

use crate::args::RulesCommand;
use crate::output::{Format, emit, table};

/// Строка списка правил.
#[derive(Debug, Serialize)]
struct RuleRow {
    id: String,
    name: String,
    priority: i32,
    condition: String,
    action: String,
}

/// Выполняет команду.
pub fn run(config: &RootConfig, command: &RulesCommand, format: Format) -> Result<()> {
    let active = config
        .active()
        .map(|p| OutboundId::from(p.id.clone()))
        .unwrap_or_else(OutboundId::direct);

    let router = Router::new(&config.routing, active, &CompileContext::default())
        .context("не удалось собрать правила")?;

    match command {
        RulesCommand::List => list(&router, format),
        RulesCommand::Explain {
            destination,
            process,
            udp,
        } => explain_flow(&router, destination, process.as_deref(), *udp, format),
    }
}

fn list(router: &Router, format: Format) -> Result<()> {
    let rows: Vec<RuleRow> = router
        .rule_set()
        .rules()
        .iter()
        .map(|rule| RuleRow {
            id: rule.id.to_string(),
            name: rule.name.clone(),
            priority: rule.priority,
            condition: rule.condition.describe(),
            action: format!("{:?}", rule.action),
        })
        .collect();

    emit(format, &rows, |rows| {
        if rows.is_empty() {
            return format!(
                "Правил нет. Весь трафик идёт по умолчанию режима `{}`.",
                router.mode().as_str()
            );
        }
        let table_rows: Vec<Vec<String>> = rows
            .iter()
            .map(|r| {
                vec![
                    r.priority.to_string(),
                    r.name.clone(),
                    r.condition.clone(),
                    r.action.clone(),
                ]
            })
            .collect();
        // Порядок строк — тот же, в каком правила разбираются. Это не
        // оформление, а смысл: разбирает набор именно порядок.
        table(
            &["приоритет", "правило", "условие", "действие"],
            &table_rows,
        )
    });
    Ok(())
}

fn explain_flow(
    router: &Router,
    destination: &str,
    process: Option<&str>,
    udp: bool,
    format: Format,
) -> Result<()> {
    let target: SocketAddress = destination
        .parse()
        .with_context(|| format!("не разбирается адрес `{destination}`"))?;

    let network = if udp { Network::Udp } else { Network::Tcp };
    let mut flow = FlowContext::to_target(
        network,
        // Источник в правилах не участвует; подставляется что угодно
        // осмысленное. Собирается, а не разбирается из строки: разбор
        // литерала — это `expect` на пути, который обязан не паниковать.
        SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 0),
        target,
    );

    if let Some(path) = process {
        // Пользователь пишет и полный путь, и просто имя файла. Личность
        // строится из того, что дали: имя выведется из пути само.
        flow = flow.with_process(ProcessIdentity::new(0, path));
    }

    let explanation = explain(router, &flow);
    emit(format, &explanation, render_explanation);
    Ok(())
}

fn render_explanation(explanation: &Explanation) -> String {
    let mut out = format!(
        "Решение: {}\nПричина: {}\n",
        explanation.decision, explanation.reason
    );

    if explanation.rules.is_empty() {
        out.push_str("\nПравил нет.");
        return out;
    }

    let rows: Vec<Vec<String>> = explanation
        .rules
        .iter()
        .map(|rule| {
            // Три состояния, а не два: «сработало» и «сработало бы, не будь
            // предыдущего» — разные вещи, и именно во втором чаще всего и
            // кроется неожиданный исход.
            let mark = match (rule.decisive, rule.matched) {
                (true, _) => "→",
                (false, true) => "·",
                (false, false) => " ",
            };
            vec![mark.to_owned(), rule.name.clone(), rule.condition.clone()]
        })
        .collect();

    out.push('\n');
    out.push_str(&table(&["", "правило", "условие"], &rows));
    out.push_str("\n\n→ сработало · подошло, но не первым");
    out
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::rule::RuleConfig;
    use serde_json::json;

    use super::*;

    fn config(rules: serde_json::Value) -> RootConfig {
        let rules: Vec<RuleConfig> = serde_json::from_value(rules).expect("правила разбираются");
        let mut config = RootConfig::default();
        config.routing.rules = rules;
        config
    }

    fn router_of(config: &RootConfig) -> Router {
        Router::new(
            &config.routing,
            OutboundId::new("home"),
            &CompileContext::default(),
        )
        .expect("собирается")
    }

    #[test]
    fn explains_a_domain_flow() {
        let config = config(json!([
            { "id": "r1", "name": "Игры мимо", "when": { "process_name": ["steam.exe"] }, "action": "direct" }
        ]));
        let router = router_of(&config);

        let flow = FlowContext::to_target(
            Network::Tcp,
            "127.0.0.1:0".parse().expect("адрес"),
            "example.com:443".parse().expect("адрес"),
        )
        .with_process(ProcessIdentity::new(0, "c:/steam/steam.exe"));

        let explanation = explain(&router, &flow);
        assert_eq!(explanation.decision, "direct");
        assert_eq!(explanation.reason, "правило «Игры мимо»");
    }

    #[test]
    fn rendering_marks_the_decisive_rule() {
        let config = config(json!([
            { "id": "первое", "priority": -1, "name": "Первое", "when": { "dest_port": [443] }, "action": "direct" },
            { "id": "второе", "name": "Второе", "when": { "dest_port": [443] }, "action": "block" }
        ]));
        let router = router_of(&config);

        let flow = FlowContext::to_target(
            Network::Tcp,
            "127.0.0.1:0".parse().expect("адрес"),
            "example.com:443".parse().expect("адрес"),
        );

        let rendered = render_explanation(&explain(&router, &flow));
        assert!(rendered.contains("→"), "сработавшее правило не отмечено");
        assert!(
            rendered.contains("·"),
            "подошедшее, но не первое, не отмечено"
        );
    }

    #[test]
    fn bad_destination_is_reported_clearly() {
        let config = config(json!([]));
        let router = router_of(&config);
        let err = explain_flow(&router, "без-порта", None, false, Format::Text)
            .expect_err("адрес не разбирается");
        assert!(err.to_string().contains("без-порта"));
    }

    #[test]
    fn empty_ruleset_says_so() {
        let config = config(json!([]));
        let router = router_of(&config);
        let flow = FlowContext::to_target(
            Network::Tcp,
            "127.0.0.1:0".parse().expect("адрес"),
            "example.com:443".parse().expect("адрес"),
        );
        let rendered = render_explanation(&explain(&router, &flow));
        assert!(rendered.contains("Правил нет"));
    }
}
