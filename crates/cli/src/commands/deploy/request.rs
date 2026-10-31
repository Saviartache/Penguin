//! Запрос на развёртывание и его проверка без сети.

use std::fmt;

use serde::Deserialize;

/// Что и куда ставить; читается из stdin, чтобы пароль не попал в список процессов.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Адрес сервера для `ssh`.
    pub host: String,
    /// Порт `ssh`.
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    /// Пользователь `ssh`; не `root` — нужен `sudo` без пароля.
    #[serde(default = "default_ssh_user")]
    pub ssh_user: String,
    /// Пароль `ssh`; без него и без ключа — как настроено у `ssh` (агент).
    #[serde(default)]
    pub password: Option<String>,
    /// Файл ключа `ssh`.
    #[serde(default)]
    pub key_file: Option<String>,
    /// Доменное имя сервера.
    pub domain: String,
    /// Порт клиентов.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Почта для Let's Encrypt.
    #[serde(default)]
    pub email: Option<String>,
    /// Пользователь Pingwin, для которого ссылка.
    #[serde(default = "default_user")]
    pub user: String,
    /// Имя профиля в клиенте.
    #[serde(default)]
    pub profile: Option<String>,
}

fn default_ssh_port() -> u16 {
    22
}

fn default_ssh_user() -> String {
    "root".to_owned()
}

fn default_port() -> u16 {
    443
}

fn default_user() -> String {
    "client".to_owned()
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("host", &self.host)
            .field("ssh_port", &self.ssh_port)
            .field("ssh_user", &self.ssh_user)
            .field("password", &self.password.as_ref().map(|_| "<скрыт>"))
            .field("key_file", &self.key_file)
            .field("domain", &self.domain)
            .field("port", &self.port)
            .field("email", &self.email)
            .field("user", &self.user)
            .field("profile", &self.profile)
            .finish()
    }
}

/// Чем плох запрос.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RequestError {
    /// Адрес сервера пуст, с пробелом или похож на флаг.
    #[error("адрес сервера пуст, с пробелом или начинается с «-»")]
    Host,
    /// Имя пользователя `ssh` вне допустимого набора.
    #[error("пользователь SSH: латиница, цифры, точка, дефис, подчёркивание")]
    SshUser,
    /// Имя сервера не доменное.
    #[error("имя «{0}» не похоже на доменное")]
    Domain(String),
    /// Порт ноль.
    #[error("порт вне 1–65535")]
    Port,
    /// Имя пользователя Pingwin вне допустимого набора.
    #[error("имя пользователя: латиница, цифры, точка, дефис, подчёркивание")]
    User,
    /// Управляющий символ или апостроф в тексте.
    #[error("в поле «{0}» управляющий символ или апостроф")]
    Text(&'static str),
    /// И пароль, и ключ сразу.
    #[error("нужен либо пароль, либо файл ключа, но не оба")]
    BothSecrets,
}

impl Request {
    /// Проверяет всё, что видно без сети.
    pub fn validate(&self) -> Result<(), RequestError> {
        if self.host.is_empty()
            || self.host.starts_with('-')
            || self.host.chars().any(char::is_whitespace)
        {
            return Err(RequestError::Host);
        }
        if !is_name(&self.ssh_user) || self.ssh_user.starts_with('-') {
            return Err(RequestError::SshUser);
        }
        if !is_domain(&self.domain) {
            return Err(RequestError::Domain(self.domain.clone()));
        }
        if self.ssh_port == 0 || self.port == 0 {
            return Err(RequestError::Port);
        }
        if !is_name(&self.user) {
            return Err(RequestError::User);
        }
        for (field, value) in [("profile", &self.profile), ("email", &self.email)] {
            if value.as_deref().is_some_and(|text| !is_plain(text)) {
                return Err(RequestError::Text(field));
            }
        }
        if self.password.is_some() && self.key_file.is_some() {
            return Err(RequestError::BothSecrets);
        }
        Ok(())
    }
}

/// `[A-Za-z0-9._-]+`.
fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// `^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$` — как проверяет `install.sh`.
fn is_domain(text: &str) -> bool {
    let Some((head, tld)) = text.rsplit_once('.') else {
        return false;
    };
    !head.is_empty()
        && head
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        && tld.len() >= 2
        && tld.chars().all(|c| c.is_ascii_alphabetic())
}

fn is_plain(text: &str) -> bool {
    !text.chars().any(|c| c.is_control() || c == '\'')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(json: &str) -> Request {
        serde_json::from_str(json).expect("запрос разбирается")
    }

    #[test]
    fn defaults_fill_the_gaps() {
        let request = request(r#"{"host":"203.0.113.5","domain":"vpn.example.com"}"#);
        assert_eq!(request.ssh_port, 22);
        assert_eq!(request.ssh_user, "root");
        assert_eq!(request.port, 443);
        assert_eq!(request.user, "client");
        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(
            serde_json::from_str::<Request>(r#"{"host":"h","domain":"a.io","pass":"x"}"#).is_err()
        );
    }

    #[test]
    fn debug_hides_the_password() {
        let request =
            request(r#"{"host":"h","domain":"vpn.example.com","password":"hunter2-secret"}"#);
        let printed = format!("{request:?}");
        assert!(!printed.contains("hunter2"));
        assert!(printed.contains("<скрыт>"));
    }

    #[test]
    fn validation_catches_what_is_visible_offline() {
        let cases = [
            (r#"{"host":"","domain":"a.io"}"#, RequestError::Host),
            (r#"{"host":"-oProxy","domain":"a.io"}"#, RequestError::Host),
            (r#"{"host":"a b","domain":"a.io"}"#, RequestError::Host),
            (
                r#"{"host":"h","ssh_user":"-x","domain":"a.io"}"#,
                RequestError::SshUser,
            ),
            (
                r#"{"host":"h","ssh_user":"a;b","domain":"a.io"}"#,
                RequestError::SshUser,
            ),
            (
                r#"{"host":"h","domain":"localhost"}"#,
                RequestError::Domain("localhost".into()),
            ),
            (
                r#"{"host":"h","domain":"a.io","port":0}"#,
                RequestError::Port,
            ),
            (
                r#"{"host":"h","domain":"a.io","ssh_port":0}"#,
                RequestError::Port,
            ),
            (
                r#"{"host":"h","domain":"a.io","user":"a b"}"#,
                RequestError::User,
            ),
            (
                r#"{"host":"h","domain":"a.io","profile":"it's"}"#,
                RequestError::Text("profile"),
            ),
            (
                r#"{"host":"h","domain":"a.io","email":"a\nb"}"#,
                RequestError::Text("email"),
            ),
            (
                r#"{"host":"h","domain":"a.io","password":"p","key_file":"k"}"#,
                RequestError::BothSecrets,
            ),
        ];
        for (json, error) in cases {
            assert_eq!(request(json).validate(), Err(error), "{json}");
        }
    }

    #[test]
    fn domains_follow_the_script() {
        assert!(is_domain("vpn.example.com"));
        assert!(is_domain("a-b.c.de"));
        assert!(!is_domain("xn--80a.xn--p1ai"));
        assert!(!is_domain("a.i0"));
        assert!(!is_domain(".io"));
        assert!(!is_domain("a.b"));
        assert!(!is_domain("a_b.com"));
    }
}
