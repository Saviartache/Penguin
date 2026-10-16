//! Таблица пользователей: метка (считается при запуске) → имя и пароль.

use std::collections::HashMap;

use anyhow::{Result, bail};
use penguin_pingwin::wire::keys::{self, PUBLIC_LEN, USER_LEN};

use crate::config::ServerConfig;

/// Кого пускать.
pub struct Policy {
    users: HashMap<[u8; USER_LEN], (String, Vec<u8>)>,
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("users", &self.users.len())
            .finish()
    }
}

impl Policy {
    /// Собирает таблицу; `Err` — у двух пользователей одна метка (пароль).
    pub fn new(config: &ServerConfig, server_public: &[u8; PUBLIC_LEN]) -> Result<Self> {
        let mut users = HashMap::with_capacity(config.users.len());
        for user in &config.users {
            let tag = keys::user_tag(user.password.as_bytes(), server_public)
                .map_err(|err| anyhow::anyhow!("метка пользователя `{}`: {err}", user.name))?;
            let entry = (user.name.clone(), user.password.as_bytes().to_vec());
            if let Some((existing, _)) = users.insert(tag, entry) {
                bail!("у пользователей `{existing}` и `{}` одна метка", user.name);
            }
        }
        Ok(Self { users })
    }

    /// Пароль по метке.
    pub fn password(&self, user: &[u8; USER_LEN]) -> Option<&[u8]> {
        self.users
            .get(user)
            .map(|(_, password)| password.as_slice())
    }

    /// Имя по метке — только для журнала.
    pub fn name(&self, user: &[u8; USER_LEN]) -> Option<&str> {
        self.users.get(user).map(|(name, _)| name.as_str())
    }

    /// Сколько пользователей знает сервер.
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Пользователей нет вовсе.
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::User;

    fn config(users: &[(&str, &str)]) -> ServerConfig {
        ServerConfig {
            listen: "0.0.0.0:443".to_owned(),
            key: penguin_core::base64::encode(&[7u8; 32]),
            cert: "c".into(),
            cert_key: "k".into(),
            cover: None,
            users: users
                .iter()
                .map(|(name, password)| User {
                    name: (*name).to_owned(),
                    password: (*password).to_owned(),
                })
                .collect(),
        }
    }

    #[test]
    fn a_known_password_is_found_by_its_tag() {
        let public = [3u8; PUBLIC_LEN];
        let policy = Policy::new(&config(&[("petya", "secret")]), &public).expect("собирается");
        let tag = keys::user_tag(b"secret", &public).expect("считается");

        assert_eq!(policy.password(&tag), Some(b"secret".as_slice()));
        assert_eq!(policy.name(&tag), Some("petya"));
        assert!(policy.password(&[0u8; USER_LEN]).is_none());
    }

    #[test]
    fn two_users_with_the_same_password_are_refused_by_name() {
        let err = Policy::new(&config(&[("petya", "same"), ("vasya", "same")]), &[3u8; 32])
            .expect_err("метки совпали");
        assert!(err.to_string().contains("vasya"));
    }
}
