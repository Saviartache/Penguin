//! Параметры: адрес сервера, имя пользователя, пароль или ключ, отпечаток хоста.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use russh::keys::PrivateKey;
use serde::{Deserialize, Serialize};

use crate::error::{SshError, SshResult};
use crate::fingerprint::HostFingerprint;

/// Настройки подключения к серверу SSH.
///
/// `Debug` реализован вручную ниже: производный вывел бы пароль и ключ в
/// журнал (`AGENTS.md` §5.2).
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshConfig {
    /// Адрес сервера: `example.com:22`.
    pub server: String,

    /// Имя пользователя.
    pub username: String,

    /// Пароль. Ровно один из пароля и ключа должен быть задан.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Приватный ключ целиком — PEM, OpenSSH или PuTTY, любой из тех, что
    /// понимает `ssh-keygen`. Путь к файлу не подходит: конфигурацию можно
    /// перенести на другую машину, а файл — не всегда.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,

    /// Пароль к приватному ключу, если он зашифрован.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_passphrase: Option<String>,

    /// Отпечаток хоста: строка `ssh-keyscan`/`known_hosts` или строка
    /// `ssh-keygen -l` (`SHA256:...`). Обязателен — см. [`crate::fingerprint`].
    pub host_fingerprint: String,
}

impl SshConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> SshResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| SshError::config(format!("адрес сервера `{raw}`: {e}")))?;

        // Смена порта на ходу — не про SSH: соединение и так одно на весь
        // профиль, менять в нём нечего.
        if endpoint.ports.is_hopping() {
            return Err(SshError::config(
                "SSH не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Разбирает отпечаток хоста.
    pub fn host_fingerprint(&self) -> SshResult<HostFingerprint> {
        HostFingerprint::parse(&self.host_fingerprint)
    }

    /// Разбирает приватный ключ, если он задан.
    ///
    /// Неверный пароль к зашифрованному ключу и попросту не тот формат здесь
    /// неразличимы — сама библиотека их не различает, — и оба остаются
    /// ошибкой настроек: сервер тут ни при чём, до него дело не дошло.
    pub fn private_key(&self) -> SshResult<Option<PrivateKey>> {
        match &self.private_key {
            Some(pem) => {
                let key =
                    russh::keys::decode_secret_key(pem, self.private_key_passphrase.as_deref())
                        .map_err(|e| {
                            SshError::config(format!("приватный ключ не разбирается: {e}"))
                        })?;
                Ok(Some(key))
            }
            None => Ok(None),
        }
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> SshResult<()> {
        self.endpoint()?;
        self.host_fingerprint()?;

        if self.username.trim().is_empty() {
            return Err(SshError::config(
                "имя пользователя не задано: сервер отличает своих по нему",
            ));
        }

        let has_password = self.password.as_deref().is_some_and(|p| !p.is_empty());
        let has_key = self
            .private_key
            .as_deref()
            .is_some_and(|k| !k.trim().is_empty());

        if !has_password && !has_key {
            return Err(SshError::config(
                "нужен пароль или приватный ключ: без одного из них опознаться нечем",
            ));
        }
        if has_password && has_key {
            return Err(SshError::config(
                "заданы и пароль, и приватный ключ: оставьте один способ опознания, \
                 иначе неясно, каким пробовать",
            ));
        }
        if !has_key && self.private_key_passphrase.is_some() {
            return Err(SshError::config(
                "пароль ключа задан, а самого ключа нет: поле не к чему применить",
            ));
        }

        if has_key {
            self.private_key()?;
        }
        Ok(())
    }
}

// Пароль и ключ не должны попасть в журнал ни целиком, ни частями.
impl std::fmt::Debug for SshConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConfig")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<скрыт>"))
            .field("private_key", &self.private_key.as_ref().map(|_| "<скрыт>"))
            .field(
                "private_key_passphrase",
                &self.private_key_passphrase.as_ref().map(|_| "<скрыт>"),
            )
            .field("host_fingerprint", &self.host_fingerprint)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const FINGERPRINT: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";

    // Не настоящий ключ: тесту ниже нужно только то, что `Debug` не печатает
    // это поле как есть, а не то, что оно разбирается.
    const FAKE_KEY: &str =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n";

    fn config() -> SshConfig {
        SshConfig {
            server: "example.com:22".to_owned(),
            username: "penguin".to_owned(),
            password: Some("secret".to_owned()),
            host_fingerprint: FINGERPRINT.to_owned(),
            ..SshConfig::default()
        }
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config().endpoint().expect("разбирается");
        assert_eq!(host.as_domain(), Some("example.com"));
        assert_eq!(port, 22);

        let config = SshConfig {
            server: "[2001:db8::1]:22".to_owned(),
            ..config()
        };
        assert!(config.endpoint().expect("разбирается").0.as_ip().is_some());
    }

    #[test]
    fn a_port_range_is_refused() {
        let config = SshConfig {
            server: "example.com:20000-30000".to_owned(),
            ..config()
        };
        assert!(config.endpoint().is_err());
    }

    #[test]
    fn an_empty_username_is_refused() {
        let config = SshConfig {
            username: "  ".to_owned(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn neither_a_password_nor_a_key_is_refused() {
        let config = SshConfig {
            password: None,
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn both_a_password_and_a_key_are_refused() {
        // Неясно, каким пробовать: молчаливый выбор одного из двух был бы
        // сюрпризом для того, кто заполнил оба поля не по ошибке.
        let config = SshConfig {
            private_key: Some("что-то".to_owned()),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_passphrase_without_a_key_is_refused() {
        let config = SshConfig {
            private_key_passphrase: Some("secret".to_owned()),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_unparseable_private_key_is_refused() {
        let config = SshConfig {
            password: None,
            private_key: Some("не ключ".to_owned()),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_missing_host_fingerprint_is_refused() {
        // Отпечаток обязателен: без него SSH — это `insecure`, только молчаливый.
        let config = SshConfig {
            host_fingerprint: String::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_unparseable_host_fingerprint_is_refused() {
        let config = SshConfig {
            host_fingerprint: "мусор".to_owned(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let params = json!({
            "server": "example.com:22",
            "username": "penguin",
            "password": "secret",
            "host_fingerprint": FINGERPRINT,
            "usernam": "опечатка"
        });
        assert!(serde_json::from_value::<SshConfig>(params).is_err());
    }

    #[test]
    fn the_password_and_the_key_never_show_up_in_the_log() {
        let config = SshConfig {
            private_key: Some(FAKE_KEY.to_owned()),
            private_key_passphrase: Some("secret".to_owned()),
            ..config()
        };
        let shown = format!("{config:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(!shown.contains("BEGIN OPENSSH"), "{shown}");
        // Отпечаток — не секрет, скрывать его незачем.
        assert!(shown.contains("ssh-ed25519"), "{shown}");
    }
}
