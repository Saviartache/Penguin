//! Черновик профиля: что набрали в форме сервера и во что это превращается.
//!
//! Имена полей совпадают с конфигурацией официального клиента Hysteria 2:
//! пользователь приносит настройки от провайдера и переносит их по одному, не
//! гадая, что чему соответствует.

use penguin_config::schema::outbound::RawOutbound;
use penguin_config::schema::profile::Profile;
use penguin_core::id::ProfileId;
use serde_json::json;

/// Какое поле правится.
///
/// Перечислением, а не отдельным сообщением на поле: восемь почти одинаковых
/// вариантов в `Message` читаются хуже одного с уточнением.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// Имя профиля.
    Name,
    /// Адрес сервера.
    Server,
    /// Пароль.
    Password,
    /// Имя для TLS.
    Sni,
    /// Пароль обфускации.
    Obfs,
    /// Отдача.
    Up,
    /// Приём.
    Down,
}

/// Что набрано в редакторе.
#[derive(Debug, Clone, Default)]
pub struct Draft {
    /// Какой профиль правится. `None` — новый.
    pub id: Option<String>,
    /// Имя профиля.
    pub name: String,
    /// `example.com:443` или `example.com:20000-30000`.
    pub server: String,
    /// Пароль.
    pub password: String,
    /// Имя для TLS, если отличается от адреса.
    pub sni: String,
    /// Пароль обфускации Salamander. Пусто — без обфускации.
    pub obfs: String,
    /// Отдача: `50 mbps`.
    pub up: String,
    /// Приём: `200 mbps`.
    pub down: String,
    /// Не проверять сертификат.
    pub insecure: bool,
}

impl Draft {
    /// Заполняет редактор из существующего профиля.
    ///
    /// Пароль тоже: иначе правка имени стирала бы пароль, и узналось бы это
    /// только при следующем подключении.
    pub fn from_profile(profile: &Profile) -> Self {
        let field = |name: &str| {
            profile
                .outbound
                .field(name)
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_owned()
        };
        let nested = |group: &str, name: &str| {
            profile
                .outbound
                .field(group)
                .and_then(|value| value.get(name))
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_owned()
        };

        Self {
            id: Some(profile.id.as_str().to_owned()),
            name: profile.name.clone(),
            server: field("server"),
            // `auth` — псевдоним `password` в файле от провайдера.
            password: if field("password").is_empty() {
                field("auth")
            } else {
                field("password")
            },
            sni: nested("tls", "sni"),
            obfs: nested("obfs", "password"),
            up: nested("bandwidth", "up"),
            down: nested("bandwidth", "down"),
            insecure: profile
                .outbound
                .field("tls")
                .and_then(|value| value.get("insecure"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        }
    }

    /// Правится ли существующий профиль.
    pub fn is_edit(&self) -> bool {
        self.id.is_some()
    }

    /// Значение поля.
    pub fn get(&self, field: Field) -> &str {
        match field {
            Field::Name => &self.name,
            Field::Server => &self.server,
            Field::Password => &self.password,
            Field::Sni => &self.sni,
            Field::Obfs => &self.obfs,
            Field::Up => &self.up,
            Field::Down => &self.down,
        }
    }

    /// Записывает значение в поле.
    pub fn set(&mut self, field: Field, value: String) {
        match field {
            Field::Name => self.name = value,
            Field::Server => self.server = value,
            Field::Password => self.password = value,
            Field::Sni => self.sni = value,
            Field::Obfs => self.obfs = value,
            Field::Up => self.up = value,
            Field::Down => self.down = value,
        }
    }

    /// Собирает профиль.
    ///
    /// `Err` — текст, который можно показать как есть: разбирать код ошибки в
    /// интерфейсе всё равно некому.
    pub fn to_profile(&self) -> Result<Profile, String> {
        let server = self.server.trim();
        if server.is_empty() {
            return Err(crate::i18n::s().need_server.to_owned());
        }
        check_server(server)?;
        if self.password.trim().is_empty() {
            return Err(crate::i18n::s().need_password.to_owned());
        }

        let mut params = serde_json::Map::new();
        params.insert("server".to_owned(), json!(server));
        params.insert("password".to_owned(), json!(self.password.trim()));

        // Пустые группы не пишутся: пустой `tls` в файле выглядит как
        // настройка, которую кто-то трогал.
        if !self.sni.trim().is_empty() || self.insecure {
            params.insert(
                "tls".to_owned(),
                object([
                    ("sni", non_empty(&self.sni).map(|sni| json!(sni))),
                    ("insecure", Some(json!(self.insecure))),
                ]),
            );
        }
        if !self.obfs.trim().is_empty() {
            params.insert(
                "obfs".to_owned(),
                json!({ "type": "salamander", "password": self.obfs.trim() }),
            );
        }
        if !self.up.trim().is_empty() || !self.down.trim().is_empty() {
            params.insert(
                "bandwidth".to_owned(),
                object([
                    ("up", non_empty(&self.up).map(|up| json!(up))),
                    ("down", non_empty(&self.down).map(|down| json!(down))),
                ]),
            );
        }

        let name = if self.name.trim().is_empty() {
            // Безымянный профиль неотличим в списке от соседнего; адрес
            // сервера — единственное, что про него точно известно.
            server.to_owned()
        } else {
            self.name.trim().to_owned()
        };
        let id = self.id.clone().unwrap_or_else(|| slug(&name));

        Ok(Profile::new(
            ProfileId::new(id),
            name,
            RawOutbound::new("hysteria2", serde_json::Value::Object(params)),
        ))
    }
}

/// Значение или `null`, чтобы необязательное поле не превратилось в пустую
/// строку — её протокол попытается разобрать и откажет.
/// Складывает объект из тех полей, что заданы.
///
/// Пропущенное поле **пропускается**, а не пишется пустым. Разница не
/// косметическая: настройки лежат в TOML, а в нём пустого значения не
/// существует вовсе. `serde_json::Value::Null` сериализуется как «единица», и
/// `toml` отвечает `unsupported unit type` — профиль перестаёт сохраняться
/// целиком, причём молча для того, кто просто не заполнил необязательное поле.
fn object(
    fields: impl IntoIterator<Item = (&'static str, Option<serde_json::Value>)>,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (name, value) in fields {
        if let Some(value) = value {
            map.insert(name.to_owned(), value);
        }
    }
    serde_json::Value::Object(map)
}

fn non_empty(value: &str) -> Option<&str> {
    Some(value.trim()).filter(|value| !value.is_empty())
}

/// Проверяет адрес сервера.
///
/// Разбор идёт типами [`penguin_core`] — теми же, которыми пользуется сам
/// протокол. Позвать протокол напрямую было бы точнее, но окно не имеет права
/// о нём знать: `protocols/*` подключает один только `engine` (см. `AGENTS.md`),
/// иначе каждый новый протокол правил бы ещё и интерфейс.
fn check_server(raw: &str) -> Result<(), String> {
    let (host, ports) = match raw.strip_prefix('[') {
        // IPv6 в скобках: `[::1]:443`. Без этого разбора двоеточия адреса
        // приняли бы за разделитель порта.
        Some(rest) => match rest.split_once("]:") {
            Some(parts) => parts,
            None => return Err(crate::i18n::s().bad_server.to_owned()),
        },
        None => match raw.rsplit_once(':') {
            Some(parts) => parts,
            None => return Err(crate::i18n::s().bad_server.to_owned()),
        },
    };

    host.parse::<penguin_core::address::Address>()
        .map_err(|err| err.to_string())?;
    ports
        .parse::<penguin_core::endpoint::PortSpec>()
        .map_err(|err| err.to_string())?;
    Ok(())
}

/// Делает из имени идентификатор.
///
/// Идентификатор постоянный, а имя пользователь меняет: на него ссылаются
/// правила, и переименование сервера не должно их ломать.
pub fn slug(name: &str) -> String {
    let slug: String = name
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();

    let slug = slug.trim_matches('-').to_owned();
    if slug.is_empty() {
        "profile".to_owned()
    } else {
        slug
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Есть ли где-нибудь в значении пустота.
    fn has_null(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Null => true,
            serde_json::Value::Object(map) => map.values().any(has_null),
            serde_json::Value::Array(items) => items.iter().any(has_null),
            _ => false,
        }
    }

    #[test]
    fn an_unfilled_field_is_left_out_not_written_empty() {
        // Настройки лежат в TOML, а пустого значения в нём не существует.
        // Раньше «не заполнил SNI, но снял проверку сертификата» давало
        // `sni: null`, и профиль переставал сохраняться — с сообщением
        // `unsupported unit type`, из которого понять ничего нельзя.
        let draft = Draft {
            server: "example.com:443".to_owned(),
            password: "тайна".to_owned(),
            insecure: true,
            ..Draft::default()
        };

        let profile = draft.to_profile().expect("профиль собирается");
        assert!(
            !has_null(&profile.outbound.params),
            "в параметрах осталась пустота: {:?}",
            profile.outbound.params
        );
        assert!(profile.outbound.field("tls").is_some(), "блок TLS потерян");
    }

    #[test]
    fn one_sided_bandwidth_writes_only_its_half() {
        let draft = Draft {
            server: "example.com:443".to_owned(),
            password: "тайна".to_owned(),
            down: "100 mbps".to_owned(),
            ..Draft::default()
        };

        let profile = draft.to_profile().expect("профиль собирается");
        assert!(!has_null(&profile.outbound.params));
    }

    fn draft() -> Draft {
        Draft {
            name: "Дом".to_owned(),
            server: "example.com:443".to_owned(),
            password: "секрет".to_owned(),
            ..Draft::default()
        }
    }

    #[test]
    fn a_filled_draft_becomes_a_profile() {
        let profile = draft().to_profile().expect("профиль собирается");
        assert_eq!(profile.name, "Дом");
        assert_eq!(profile.outbound.protocol, "hysteria2");
        assert_eq!(
            profile.outbound.field("server").and_then(|v| v.as_str()),
            Some("example.com:443")
        );
    }

    #[test]
    fn a_broken_address_is_reported_before_saving() {
        // Профиль, который сохраняется, но не подключается, — худший исход:
        // виновата будет «служба».
        let mut draft = draft();
        draft.server = "просто-текст".to_owned();
        assert!(draft.to_profile().is_err());
    }

    #[test]
    fn addresses_are_checked_the_way_the_protocol_checks_them() {
        check_server("example.com:443").expect("имя и порт");
        check_server("example.com:20000-30000").expect("диапазон портов");
        check_server("[2001:db8::1]:443").expect("IPv6 в скобках");
        check_server("1.2.3.4:443").expect("адрес и порт");

        assert!(check_server("example.com").is_err(), "порт не указан");
        assert!(check_server("example.com:абв").is_err(), "порт не число");
        assert!(check_server("[2001:db8::1]").is_err(), "порт не указан");
    }

    #[test]
    fn an_empty_password_is_reported() {
        let mut draft = draft();
        draft.password = "   ".to_owned();
        assert!(draft.to_profile().is_err());
    }

    #[test]
    fn empty_groups_are_not_written() {
        // Пустой `tls` в файле выглядит как настройка, которую кто-то трогал.
        let profile = draft().to_profile().expect("профиль собирается");
        assert!(profile.outbound.field("tls").is_none());
        assert!(profile.outbound.field("obfs").is_none());
        assert!(profile.outbound.field("bandwidth").is_none());
    }

    #[test]
    fn filled_groups_are_written_and_read_back() {
        let mut draft = draft();
        draft.sni = "cdn.example.com".to_owned();
        draft.obfs = "соль".to_owned();
        draft.up = "50 mbps".to_owned();
        draft.down = "200 mbps".to_owned();
        draft.insecure = true;

        let profile = draft.to_profile().expect("профиль собирается");
        let back = Draft::from_profile(&profile);

        // Правка имени не должна стирать всё остальное.
        assert_eq!(back.sni, "cdn.example.com");
        assert_eq!(back.obfs, "соль");
        assert_eq!(back.up, "50 mbps");
        assert_eq!(back.down, "200 mbps");
        assert!(back.insecure);
        assert_eq!(back.password, "секрет");
    }

    #[test]
    fn editing_keeps_the_identifier() {
        // На идентификатор ссылаются правила; переименование сервера не должно
        // их ломать.
        let profile = draft().to_profile().expect("профиль собирается");
        let mut back = Draft::from_profile(&profile);
        back.name = "Совсем другое имя".to_owned();

        assert_eq!(back.to_profile().expect("собирается").id, profile.id);
    }

    #[test]
    fn slugs_are_usable_identifiers() {
        assert_eq!(slug("Дом"), "дом");
        assert_eq!(slug("Server #1 (RU)"), "server--1--ru");
        assert_eq!(slug("   "), "profile");
        assert_eq!(slug("---"), "profile");
    }

    #[test]
    fn a_nameless_profile_is_named_by_its_address() {
        let mut draft = draft();
        draft.name = String::new();
        assert_eq!(
            draft.to_profile().expect("собирается").name,
            "example.com:443"
        );
    }

    #[test]
    fn every_field_round_trips() {
        // Поле, которое читается не оттуда, куда пишется, — это поле, которое
        // молча теряет введённое.
        let mut draft = Draft::default();
        for field in [
            Field::Name,
            Field::Server,
            Field::Password,
            Field::Sni,
            Field::Obfs,
            Field::Up,
            Field::Down,
        ] {
            draft.set(field, format!("{field:?}"));
            assert_eq!(draft.get(field), format!("{field:?}"));
        }
    }
}
