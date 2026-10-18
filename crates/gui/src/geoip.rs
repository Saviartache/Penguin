//! Страна серверов: окно просит об этом себя-как-CLI.
//!
//! База GeoIP качается с GitHub, а имена резолвятся мимо окна (`AGENTS.md`
//! §1.7): `penguin geoip <сервер>… --json` печатает найденные страны.

use std::collections::HashMap;

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
