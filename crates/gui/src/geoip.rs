//! Страна серверов и база для правил по странам: окно просит об этом себя-как-CLI.
//!
//! База GeoIP качается с GitHub, а имена резолвятся мимо окна (`AGENTS.md`
//! §1.7): `penguin geoip <сервер>… --json` печатает найденные страны. Служба
//! каталог пользователя не читает, поэтому базу для правил ей передаёт окно.

use std::collections::HashMap;

use penguin_config::Paths;
use penguin_config::schema::rule::{Condition, Leaf, RuleConfig};
use penguin_ipc::schema::request::GEOIP_CHUNK;
use penguin_ipc::schema::{Request, Response};

/// Страны серверов `хост:порт`; ненайденных в ответе нет.
pub(crate) async fn locate(servers: Vec<String>) -> Result<HashMap<String, String>, String> {
    tokio::task::spawn_blocking(move || {
        let mut args = vec!["geoip"];
        args.extend(servers.iter().map(String::as_str));
        args.push("--json");
        let output = crate::self_exec::run_self(&args)?;
        serde_json::from_slice(&output).map_err(|err| format!("ответ GeoIP не разобран: {err}"))
    })
    .await
    .map_err(|err| err.to_string())?
}

/// Нужна ли службе база: есть включённое правило по стране.
pub(crate) fn wanted(rules: &[RuleConfig]) -> bool {
    rules
        .iter()
        .any(|rule| rule.enabled && mentions_country(&rule.when))
}

fn mentions_country(condition: &Condition) -> bool {
    match condition {
        Condition::All { all: list } | Condition::Any { any: list } => {
            list.iter().any(mentions_country)
        }
        Condition::Not { not } => mentions_country(not),
        Condition::Leaf(leaf) => matches!(leaf, Leaf::GeoIp(_)),
    }
}

/// Обновляет базу пользователя и передаёт её службе кусками.
pub(crate) async fn send_to_service() -> Result<(), String> {
    let database = tokio::task::spawn_blocking(read_database)
        .await
        .map_err(|err| err.to_string())??;
    let total = database.len() as u64;
    let mut offset = 0;
    for chunk in database.chunks(GEOIP_CHUNK) {
        let request = Request::PutGeoIp {
            offset,
            total,
            data: chunk.to_vec(),
        };
        let response = crate::ipc::client::send(request)
            .await
            .map_err(|err| err.to_string())?;
        if let Response::Error { message, .. } = response {
            return Err(message);
        }
        offset += chunk.len() as u64;
    }
    Ok(())
}

fn read_database() -> Result<Vec<u8>, String> {
    // Без серверов команда только качает базу, если она устарела.
    crate::self_exec::run_self(&["geoip", "--json"])?;
    let path = Paths::user().map_err(|err| err.to_string())?.geoip_file();
    let database = std::fs::read(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    if database.is_empty() {
        return Err(format!("{}: пустой файл", path.display()));
    }
    Ok(database)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rules(value: serde_json::Value) -> Vec<RuleConfig> {
        serde_json::from_value(value).expect("правила разбираются")
    }

    #[test]
    fn only_an_enabled_country_rule_wants_the_database() {
        let nested = rules(json!([{
            "id": "r1", "action": "direct",
            "when": { "all": [{ "dest_port": [443] }, { "any": [{ "geo_ip": ["RU"] }] }] }
        }]));
        assert!(wanted(&nested));

        let disabled = rules(json!([{
            "id": "r1", "action": "direct", "enabled": false, "when": { "geo_ip": ["RU"] }
        }]));
        assert!(!wanted(&disabled));

        let plain =
            rules(json!([{ "id": "r1", "action": "direct", "when": { "dest_port": [443] } }]));
        assert!(!wanted(&plain));
    }
}
