//! Правила сервера: кого пускать и что считать повтором.
//!
//! Крейт протокола об этом не знает намеренно (`AGENTS.md` §1.1): таблица
//! пользователей и окно повторов — это устройство сервера, а не формат
//! провода. Протокол спрашивает у правил два вопроса и не задаёт третьего.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Result, bail};
use penguin_pingwin::handshake::ServerPolicy;
use penguin_pingwin::wire::keys::{self, PUBLIC_LEN};
use penguin_pingwin::wire::replay::{ReplayWindow, now_seconds};

use crate::config::ServerConfig;

/// Таблица пользователей и окно повторов.
pub struct Policy {
    /// Метка пользователя — его имя и пароль.
    ///
    /// Метка считается один раз при запуске: считать её на каждое соединение
    /// значило бы гонять HKDF по всей таблице ради одного сравнения.
    users: HashMap<[u8; 8], (String, Vec<u8>)>,
    replay: Mutex<ReplayWindow>,
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("users", &self.users.len())
            .finish()
    }
}

impl Policy {
    /// Собирает таблицу по настройкам.
    ///
    /// `Err` — два пользователя дали одну метку. Вероятность этого ничтожна
    /// (восемь байт от HKDF), но молчаливое совпадение означало бы, что один
    /// из двоих не может подключиться никогда, — а искать такое будут долго.
    pub fn new(config: &ServerConfig, server_public: &[u8; PUBLIC_LEN]) -> Result<Self> {
        let mut users = HashMap::with_capacity(config.users.len());
        for user in &config.users {
            let tag = keys::user_tag(user.password.as_bytes(), server_public)
                .map_err(|err| anyhow::anyhow!("метка пользователя `{}`: {err}", user.name))?;
            if let Some((existing, _)) =
                users.insert(tag, (user.name.clone(), user.password.as_bytes().to_vec()))
            {
                bail!("у пользователей `{existing}` и `{}` одна метка", user.name);
            }
        }
        Ok(Self {
            users,
            replay: Mutex::new(ReplayWindow::default()),
        })
    }

    /// Имя пользователя по метке — только для журнала.
    pub fn name(&self, user: &[u8; 8]) -> Option<&str> {
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

impl ServerPolicy for Policy {
    fn password(&self, user: &[u8; 8]) -> Option<Vec<u8>> {
        self.users.get(user).map(|(_, password)| password.clone())
    }

    fn admit(&self, ephemeral: &[u8; PUBLIC_LEN], time: u64) -> bool {
        let Ok(mut replay) = self.replay.lock() else {
            // Замок сломан — значит, где-то паника. Пускать после неё нельзя:
            // окно повторов в неизвестном состоянии, а без него 0-RTT можно
            // проигрывать заново.
            return false;
        };
        let now = now_seconds();
        replay.time_is_fresh(time, now) && replay.admit(*ephemeral, now)
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
            fallback: String::new(),
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

        assert_eq!(policy.password(&tag).as_deref(), Some(b"secret".as_slice()));
        assert_eq!(policy.name(&tag), Some("petya"));
        assert!(policy.password(&[0u8; 8]).is_none());
    }

    #[test]
    fn a_hello_is_admitted_once() {
        // Повтор ранних данных закрыт здесь и только здесь: протокол сам по
        // себе о нём ничего не знает.
        let policy =
            Policy::new(&config(&[("petya", "secret")]), &[3u8; PUBLIC_LEN]).expect("собирается");
        let now = now_seconds();
        assert!(policy.admit(&[9u8; PUBLIC_LEN], now));
        assert!(!policy.admit(&[9u8; PUBLIC_LEN], now));
    }

    #[test]
    fn a_clock_that_ran_away_is_refused() {
        let policy =
            Policy::new(&config(&[("petya", "secret")]), &[3u8; PUBLIC_LEN]).expect("собирается");
        assert!(!policy.admit(&[9u8; PUBLIC_LEN], now_seconds() - 10_000));
    }

    #[test]
    fn two_users_with_the_same_password_are_refused_by_name() {
        // Метка у них одна, и второй не подключится никогда — молча.
        let err = Policy::new(&config(&[("petya", "same"), ("vasya", "same")]), &[3u8; 32])
            .expect_err("метки совпали");
        assert!(err.to_string().contains("vasya"));
    }
}
