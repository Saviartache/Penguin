//! i2pd для профилей I2P: окно просит себя-как-CLI скачать его (`AGENTS.md` §1.11),
//! а службе передаёт файл кусками — каталог пользователя она не читает.

use std::path::PathBuf;

use penguin_config::schema::profile::Profile;
use penguin_ipc::schema::request::GEOIP_CHUNK;
use penguin_ipc::schema::{Request, Response};

/// Протокол, которому нужен i2pd.
const PROTOCOL: &str = "i2p";

/// Нужен ли службе i2pd: есть профиль I2P.
pub(crate) fn wanted(profiles: &[Profile]) -> bool {
    profiles
        .iter()
        .any(|profile| profile.outbound.protocol == PROTOCOL)
}

/// Скачивает i2pd (если его нет) и передаёт службе.
pub(crate) async fn send_to_service() -> Result<(), String> {
    let binary = tokio::task::spawn_blocking(read_binary)
        .await
        .map_err(|err| err.to_string())??;
    let total = binary.len() as u64;
    let mut offset = 0;
    for chunk in binary.chunks(GEOIP_CHUNK) {
        let request = Request::PutI2pd {
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

fn read_binary() -> Result<Vec<u8>, String> {
    let output = crate::self_exec::run_self(&["i2pd", "install", "--json"])?;
    let path = path_of(&output)?;
    std::fs::read(&path).map_err(|err| format!("{}: {err}", path.display()))
}

/// Путь из ответа `penguin i2pd install --json`: `{"path": "…", "version": "…"}`.
fn path_of(output: &[u8]) -> Result<PathBuf, String> {
    let answer: serde_json::Value = serde_json::from_slice(output)
        .map_err(|err| format!("ответ `penguin i2pd install` не разобран: {err}"))?;
    answer["path"]
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| "в ответе `penguin i2pd install` нет пути".to_owned())
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::outbound::RawOutbound;
    use serde_json::json;

    use super::*;

    #[test]
    fn only_an_i2p_profile_wants_i2pd() {
        let i2p = Profile::new("i2p", "I2P", RawOutbound::new("i2p", json!({})));
        let socks = Profile::new("s", "S", RawOutbound::new("socks5", json!({})));
        assert!(wanted(&[socks.clone(), i2p]));
        assert!(!wanted(&[socks]));
    }

    #[test]
    fn the_cli_answer_names_the_file() {
        let path =
            path_of(br#"{"path":"/home/u/.local/share/penguin/i2pd/i2pd","version":"3.0.0"}"#)
                .expect("путь");
        assert_eq!(
            path,
            PathBuf::from("/home/u/.local/share/penguin/i2pd/i2pd")
        );
        assert!(path_of(b"{}").is_err());
    }
}
