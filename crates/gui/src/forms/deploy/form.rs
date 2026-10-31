//! Поля окна развёртывания и запрос, который уходит в `stdin` CLI.
//!
//! Пароль идёт через `stdin`, а не аргументом: аргументы видны всем в списке
//! процессов.

use serde_json::{Map, Value};

/// Поле окна; порядок [`Field::ALL`] — порядок в окне.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// Адрес сервера для SSH.
    Host,
    /// Порт SSH.
    SshPort,
    /// Пользователь SSH.
    SshUser,
    /// Пароль SSH; пусто — ключ или агент.
    Password,
    /// Путь к ключу SSH.
    KeyFile,
    /// Доменное имя сервера.
    Domain,
    /// Порт Pingwin.
    Port,
    /// Почта для Let's Encrypt.
    Email,
    /// Имя пользователя Pingwin.
    User,
}

impl Field {
    /// Все поля в порядке окна.
    pub const ALL: [Self; 9] = [
        Self::Host,
        Self::SshPort,
        Self::SshUser,
        Self::Password,
        Self::KeyFile,
        Self::Domain,
        Self::Port,
        Self::Email,
        Self::User,
    ];
}

/// Что набрано в окне развёртывания.
#[derive(Clone, PartialEq, Eq)]
pub struct Form {
    values: [String; Field::ALL.len()],
}

impl Default for Form {
    fn default() -> Self {
        let mut form = Self {
            values: Default::default(),
        };
        form.set(Field::SshPort, "22".to_owned());
        form.set(Field::SshUser, "root".to_owned());
        form.set(Field::Port, "443".to_owned());
        form.set(Field::User, "client".to_owned());
        form
    }
}

impl std::fmt::Debug for Form {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("Form");
        for field in Field::ALL {
            let value = if field == Field::Password {
                "***"
            } else {
                self.get(field)
            };
            debug.field(&format!("{field:?}"), &value);
        }
        debug.finish()
    }
}

impl Form {
    /// Значение поля.
    pub fn get(&self, field: Field) -> &str {
        &self.values[field as usize]
    }

    /// Ставит значение поля.
    pub fn set(&mut self, field: Field, value: String) {
        self.values[field as usize] = value;
    }

    /// Запрос для `penguin deploy pingwin --json`; `Err` — текст для показа.
    /// Пустые необязательные поля не передаются.
    pub fn request(&self, profile: &str) -> Result<String, String> {
        let strings = crate::i18n::s();
        let mut request = Map::new();
        request.insert(
            "host".to_owned(),
            required(self.get(Field::Host), strings.need_deploy_host)?,
        );
        request.insert("ssh_port".to_owned(), port(self.get(Field::SshPort))?);
        request.insert(
            "ssh_user".to_owned(),
            required(self.get(Field::SshUser), strings.need_ssh_user)?,
        );

        // Пароль как набран: пробелы в нём законны.
        let password = self.get(Field::Password);
        let key_file = self.get(Field::KeyFile).trim();
        if !password.is_empty() && !key_file.is_empty() {
            return Err(strings.password_or_key.to_owned());
        }
        optional(&mut request, "password", password);
        optional(&mut request, "key_file", key_file);

        request.insert(
            "domain".to_owned(),
            required(self.get(Field::Domain), strings.need_deploy_domain)?,
        );
        request.insert("port".to_owned(), port(self.get(Field::Port))?);
        optional(&mut request, "email", self.get(Field::Email).trim());
        request.insert(
            "user".to_owned(),
            required(self.get(Field::User), strings.need_deploy_user)?,
        );
        optional(&mut request, "profile", profile.trim());

        Ok(Value::Object(request).to_string())
    }
}

fn required(raw: &str, missing: &str) -> Result<Value, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(missing.to_owned());
    }
    Ok(Value::from(value))
}

fn optional(request: &mut Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        request.insert(key.to_owned(), Value::from(value));
    }
}

fn port(raw: &str) -> Result<Value, String> {
    raw.trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .map(Value::from)
        .ok_or_else(|| crate::i18n::s().bad_port.to_owned())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn filled() -> Form {
        let mut form = Form::default();
        form.set(Field::Host, " 203.0.113.5 ".to_owned());
        form.set(Field::Domain, "vpn.example.com".to_owned());
        form
    }

    fn parsed(form: &Form, profile: &str) -> Value {
        serde_json::from_str(&form.request(profile).expect("собирается")).expect("JSON")
    }

    #[test]
    fn defaults_and_empty_optionals_make_the_minimal_request() {
        assert_eq!(
            parsed(&filled(), " "),
            json!({
                "host": "203.0.113.5",
                "ssh_port": 22,
                "ssh_user": "root",
                "domain": "vpn.example.com",
                "port": 443,
                "user": "client",
            })
        );
    }

    #[test]
    fn optionals_are_passed_when_set() {
        let mut form = filled();
        form.set(Field::Password, " пароль ".to_owned());
        form.set(Field::Email, "me@example.com".to_owned());
        let request = parsed(&form, "Мой");
        assert_eq!(request["password"], " пароль ");
        assert_eq!(request["email"], "me@example.com");
        assert_eq!(request["profile"], "Мой");
        assert!(request.get("key_file").is_none());
    }

    #[test]
    fn required_fields_are_reported() {
        let strings = crate::i18n::s();
        assert_eq!(
            Form::default().request(""),
            Err(strings.need_deploy_host.to_owned())
        );
        let mut form = filled();
        form.set(Field::Domain, " ".to_owned());
        assert_eq!(form.request(""), Err(strings.need_deploy_domain.to_owned()));
    }

    #[test]
    fn ports_are_numbers_in_range() {
        for bad in ["0", "65536", "ssh", ""] {
            let mut form = filled();
            form.set(Field::SshPort, bad.to_owned());
            assert_eq!(
                form.request(""),
                Err(crate::i18n::s().bad_port.to_owned()),
                "`{bad}`"
            );
        }
        let mut form = filled();
        form.set(Field::Port, "8443".to_owned());
        assert_eq!(parsed(&form, "")["port"], 8443);
    }

    #[test]
    fn password_and_key_file_exclude_each_other() {
        let mut form = filled();
        form.set(Field::Password, "x".to_owned());
        form.set(Field::KeyFile, "~/.ssh/id_ed25519".to_owned());
        assert_eq!(
            form.request(""),
            Err(crate::i18n::s().password_or_key.to_owned())
        );
    }

    #[test]
    fn debug_hides_the_password() {
        let mut form = filled();
        form.set(Field::Password, "секрет-ssh".to_owned());
        let debug = format!("{form:?}");
        assert!(!debug.contains("секрет-ssh"), "{debug}");
        assert!(debug.contains("203.0.113.5"));
    }
}
