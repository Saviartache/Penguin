//! Настройки сервера: где слушать, чей ключ, кого пускать, чем прикрываться.
//!
//! ```toml
//! listen   = "0.0.0.0:443"
//! key      = "…"                # закрытый ключ, base64; выдаёт `keygen`
//! fallback = "127.0.0.1:8080"   # куда уходит всё, что не наше
//!
//! [[users]]
//! name     = "petya"
//! password = "…"
//! ```

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use penguin_pingwin::wire::keys::{KEY_LEN, StaticKeyPair};
use serde::{Deserialize, Serialize};

/// Сколько ждать рукопожатия.
///
/// Короче, чем у клиента: сервер держит тысячи соединений, и каждое
/// молчащее — это память. Тот, кто не успел, попробует ещё раз.
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);

/// Настройки сервера целиком.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Адрес и порт, на которых слушать.
    pub listen: String,

    /// Закрытый ключ сервера, тридцать два байта в base64.
    ///
    /// В `Debug` не попадает: вывод пишется вручную ниже.
    pub key: String,

    /// Куда отдавать соединения, которые не прошли опознание.
    ///
    /// Настоящий сайт — в этом весь смысл: тот, кто пробует сервер, увидит
    /// его, а не отказ. Пусто — соединение просто закрывается; так делать не
    /// стоит, и [`Self::validate`] об этом предупредит.
    #[serde(default)]
    pub fallback: String,

    /// Кого пускать.
    pub users: Vec<User>,
}

/// Один пользователь.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// Имя для журнала. На провод не попадает.
    pub name: String,
    /// Пароль. В `Debug` не попадает.
    pub password: String,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("listen", &self.listen)
            .field("key", &"<скрыт>")
            .field("fallback", &self.fallback)
            .field("users", &self.users.len())
            .finish()
    }
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("name", &self.name)
            .field("password", &"<скрыт>")
            .finish()
    }
}

impl ServerConfig {
    /// Читает настройки из файла.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("не читается файл настроек `{}`", path.display()))?;
        let config: Self = toml::from_str(&text)
            .with_context(|| format!("не разбирается файл настроек `{}`", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Адрес, на котором слушать.
    pub fn listen_addr(&self) -> Result<SocketAddr> {
        self.listen
            .trim()
            .parse()
            .with_context(|| format!("адрес `{}` не разбирается", self.listen))
    }

    /// Постоянная пара ключей сервера.
    pub fn keys(&self) -> Result<StaticKeyPair> {
        let bytes = penguin_core::base64::decode_exact(self.key.trim(), KEY_LEN, "ключ сервера")
            .map_err(|err| anyhow::anyhow!("ключ сервера: {err}"))?;
        let mut secret = [0u8; KEY_LEN];
        let chunk: &[u8; KEY_LEN] = bytes
            .first_chunk()
            .context("ключ сервера не тридцати двух байт")?;
        secret.copy_from_slice(chunk);
        Ok(StaticKeyPair::from_bytes(secret))
    }

    /// Куда отдавать чужие соединения. `None` — прикрытия нет.
    pub fn fallback_addr(&self) -> Option<&str> {
        let fallback = self.fallback.trim();
        (!fallback.is_empty()).then_some(fallback)
    }

    /// Сколько ждать рукопожатия.
    pub fn handshake_limit(&self) -> Duration {
        HANDSHAKE_LIMIT
    }

    /// Проверяет настройки, ничего не открывая.
    pub fn validate(&self) -> Result<()> {
        self.listen_addr()?;
        self.keys()?;

        if self.users.is_empty() {
            bail!("в настройках нет ни одного пользователя: пускать некого");
        }
        if let Some(empty) = self.users.iter().find(|user| user.password.is_empty()) {
            bail!("у пользователя `{}` пустой пароль", empty.name);
        }
        if self.fallback_addr().is_none() {
            // Не ошибка, но и не мелочь: сервер без прикрытия отвечает на
            // пробу закрытым соединением, и по этому его находят.
            tracing::warn!(
                "прикрытие не задано: сервер, закрывающий чужое соединение, \
                 отличим от обычного сайта"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ServerConfig {
        ServerConfig {
            listen: "0.0.0.0:443".to_owned(),
            key: penguin_core::base64::encode(&[7u8; KEY_LEN]),
            fallback: "127.0.0.1:8080".to_owned(),
            users: vec![User {
                name: "petya".to_owned(),
                password: "secret".to_owned(),
            }],
        }
    }

    #[test]
    fn a_complete_config_passes() {
        config().validate().expect("настройки верны");
    }

    #[test]
    fn a_config_without_users_is_refused() {
        // Сервер без пользователей молча не пускает никого — и разбираться с
        // этим будут по журналу клиента, а не сервера.
        let config = ServerConfig {
            users: Vec::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_empty_password_is_refused_by_name() {
        let config = ServerConfig {
            users: vec![User {
                name: "petya".to_owned(),
                password: String::new(),
            }],
            ..config()
        };
        let err = config.validate().expect_err("пароль пуст");
        assert!(err.to_string().contains("petya"));
    }

    #[test]
    fn a_broken_key_is_refused() {
        for key in ["", "не base64", &penguin_core::base64::encode(&[7u8; 31])] {
            let config = ServerConfig {
                key: key.to_owned(),
                ..config()
            };
            assert!(config.validate().is_err(), "{key}");
        }
    }

    #[test]
    fn the_config_reads_back_the_way_it_is_written() {
        // Файл настроек пишут руками: разойтись формату записи и разбора
        // нельзя.
        let text = toml::to_string(&config()).expect("записывается");
        let parsed: ServerConfig = toml::from_str(&text).expect("разбирается");
        assert_eq!(parsed.listen, config().listen);
        assert_eq!(parsed.users.len(), 1);
    }

    #[test]
    fn an_unknown_field_is_refused() {
        // Опечатка в имени поля означала бы настройку, которая выглядит
        // применённой и не применена.
        let text = "listen = \"0.0.0.0:443\"\nkey = \"x\"\nfallbak = \"y\"\nusers = []";
        assert!(toml::from_str::<ServerConfig>(text).is_err());
    }

    #[test]
    fn debug_hides_the_secrets() {
        let rendered = format!("{:?}", config());
        assert!(!rendered.contains(&config().key), "ключ в Debug");

        let user = format!("{:?}", config().users[0]);
        assert!(!user.contains("secret"), "пароль в Debug: {user}");
    }
}
