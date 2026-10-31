//! Настройки сервера: где слушать, чей ключ, какой сертификат, кого пускать.
//!
//! ```toml
//! listen   = "0.0.0.0:443"                        # UDP и TCP
//! key      = "…"                                  # закрытый ключ, base64; выдаёт `keygen`
//! cert     = "/etc/pingwin/fullchain.pem"
//! cert_key = "/etc/pingwin/privkey.pem"
//! cover    = "/srv/cover"                         # статический сайт для чужих
//!
//! [[users]]
//! name     = "petya"
//! password = "…"
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use penguin_pingwin::wire::keys::{KEY_LEN, StaticKeyPair};
use serde::{Deserialize, Serialize};

/// Настройки сервера целиком.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Адрес и порт, на которых слушать: UDP (HTTP/3) и TCP (HTTP/2).
    pub listen: String,

    /// Закрытый ключ сервера, тридцать два байта в base64.
    pub key: String,

    /// Цепочка сертификатов в PEM, лист первым.
    pub cert: PathBuf,

    /// Закрытый ключ сертификата в PEM.
    pub cert_key: PathBuf,

    /// Каталог статического сайта, который видит тот, кого не узнали.
    ///
    /// Пусто — на всё `404`. Так можно, но сайт без единой страницы
    /// выглядит странно.
    #[serde(default)]
    pub cover: Option<PathBuf>,

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
            .field("cert", &self.cert)
            .field("cert_key", &self.cert_key)
            .field("cover", &self.cover)
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
        let secret: [u8; KEY_LEN] = bytes
            .first_chunk()
            .copied()
            .context("ключ сервера не тридцати двух байт")?;
        Ok(StaticKeyPair::from_bytes(secret))
    }

    /// Проверяет настройки, не открывая сокетов. Сертификат читает
    /// [`crate::tls`].
    pub fn validate(&self) -> Result<()> {
        self.listen_addr()?;
        self.keys()?;
        if self.users.is_empty() {
            bail!("в настройках нет ни одного пользователя: пускать некого");
        }
        if let Some(empty) = self.users.iter().find(|user| user.password.is_empty()) {
            bail!("у пользователя `{}` пустой пароль", empty.name);
        }
        match &self.cover {
            Some(cover) if !cover.is_dir() => {
                bail!("прикрытие `{}` — не каталог", cover.display())
            }
            Some(_) => {}
            None => tracing::warn!("прикрытие не задано: чужой увидит сайт без единой страницы"),
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
            cert: "fullchain.pem".into(),
            cert_key: "privkey.pem".into(),
            cover: None,
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
    fn a_cover_that_is_not_a_directory_is_refused() {
        let config = ServerConfig {
            cover: Some("/нет/такого/каталога".into()),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn the_config_reads_back_the_way_it_is_written() {
        let text = toml::to_string(&config()).expect("записывается");
        let parsed: ServerConfig = toml::from_str(&text).expect("разбирается");
        assert_eq!(parsed.listen, config().listen);
        assert_eq!(parsed.users.len(), 1);
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let text = "listen = \"0.0.0.0:443\"\nkey = \"x\"\ncert = \"a\"\ncert_key = \"b\"\n\
                    fallback = \"y\"\nusers = []";
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
