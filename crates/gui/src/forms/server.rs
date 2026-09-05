//! Черновик профиля: что набрали в форме сервера и во что это превращается.
//!
//! Полей у формы нет — они приходят описанием протокола
//! ([`crate::forms::protocol`]). До этого `Draft` знал поля Hysteria 2
//! поимённо, и добавление второго протокола означало правку самого черновика,
//! редактора, сообщений и всех их тестов разом.
//!
//! # Профиль протокола, которого окно не знает
//!
//! Настройки может написать рукой человек или прислать новая версия. Такой
//! профиль показывается в списке и правится по имени, а его параметры
//! **сохраняются как есть** ([`Body::Foreign`]). Выбор здесь простой: либо
//! окно бережёт то, чего не понимает, либо переименование сервера стирает
//! половину его настроек — и узнаётся это при следующем подключении.

use penguin_config::schema::outbound::RawOutbound;
use penguin_config::schema::profile::Profile;
use penguin_core::id::ProfileId;

use crate::forms::protocol::{self, FieldSpec, ProtocolSpec};

/// Значение одного поля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Строка.
    Text(String),
    /// Переключатель.
    Flag(bool),
}

impl Value {
    /// Строка, если это строка.
    pub fn text(&self) -> &str {
        match self {
            Self::Text(value) => value,
            Self::Flag(_) => "",
        }
    }

    /// Положение переключателя, если это переключатель.
    pub fn flag(&self) -> bool {
        match self {
            Self::Flag(value) => *value,
            Self::Text(_) => false,
        }
    }
}

/// Чем заполнен черновик.
#[derive(Debug, Clone, PartialEq)]
enum Body {
    /// Протокол известен: значения лежат по полям его описания.
    Known {
        spec: &'static ProtocolSpec,
        /// Значения в том же порядке, что и [`ProtocolSpec::fields`].
        values: Vec<Value>,
    },
    /// Протокол окну неизвестен: параметры держатся нетронутыми.
    Foreign {
        protocol: String,
        params: serde_json::Value,
    },
}

/// Что набрано в редакторе.
#[derive(Debug, Clone, PartialEq)]
pub struct Draft {
    /// Какой профиль правится. `None` — новый.
    pub id: Option<String>,
    /// Имя профиля.
    pub name: String,
    body: Body,
}

impl Default for Draft {
    fn default() -> Self {
        Self::new(protocol::DEFAULT)
    }
}

impl Draft {
    /// Пустой черновик выбранного протокола.
    pub fn new(spec: &'static ProtocolSpec) -> Self {
        Self {
            id: None,
            name: String::new(),
            body: Body::Known {
                spec,
                values: spec.fields.iter().map(blank).collect(),
            },
        }
    }

    /// Заполняет редактор из существующего профиля.
    ///
    /// Пароль тоже: иначе правка имени стирала бы пароль, и узналось бы это
    /// только при следующем подключении.
    pub fn from_profile(profile: &Profile) -> Self {
        let params = &profile.outbound.params;

        let body = match protocol::by_id(&profile.outbound.protocol) {
            Some(spec) => Body::Known {
                spec,
                values: spec
                    .fields
                    .iter()
                    .map(|field| read(field, params))
                    .collect(),
            },
            None => Body::Foreign {
                protocol: profile.outbound.protocol.clone(),
                params: params.clone(),
            },
        };

        Self {
            id: Some(profile.id.as_str().to_owned()),
            name: profile.name.clone(),
            body,
        }
    }

    /// Правится ли существующий профиль.
    pub fn is_edit(&self) -> bool {
        self.id.is_some()
    }

    /// Имя протокола, как оно лежит в настройках.
    pub fn protocol(&self) -> &str {
        match &self.body {
            Body::Known { spec, .. } => spec.id,
            Body::Foreign { protocol, .. } => protocol,
        }
    }

    /// Описание протокола. `None` — окно его не знает.
    pub fn spec(&self) -> Option<&'static ProtocolSpec> {
        match &self.body {
            Body::Known { spec, .. } => Some(spec),
            Body::Foreign { .. } => None,
        }
    }

    /// Поля формы. У неизвестного протокола их нет — только имя.
    pub fn fields(&self) -> &'static [FieldSpec] {
        self.spec().map_or(&[], |spec| spec.fields)
    }

    /// Ставит идентификатор правящегося профиля.
    ///
    /// Нужно ровно там, где черновик заменяют целиком — при вставке ссылки:
    /// на идентификатор ссылаются правила, и новый сервер по ссылке не должен
    /// их ломать.
    pub fn with_id(mut self, id: Option<String>) -> Self {
        self.id = id;
        self
    }

    /// Значение поля по имени.
    pub fn text(&self, key: &str) -> &str {
        self.at(key).map_or("", Value::text)
    }

    /// Положение переключателя по имени.
    pub fn flag(&self, key: &str) -> bool {
        self.at(key).is_some_and(Value::flag)
    }

    /// Записывает строку в поле по его месту в форме.
    ///
    /// Место, а не имя: сообщение о правке приходит от виджета, который знает
    /// только свой номер в форме. Номер за пределами формы пропускается —
    /// такое сообщение могло уехать до смены протокола.
    pub fn set_at(&mut self, index: usize, value: String) {
        if let Body::Known { values, .. } = &mut self.body
            && let Some(slot) = values.get_mut(index)
        {
            *slot = Value::Text(value);
        }
    }

    /// Переключает флажок по его месту в форме.
    pub fn toggle_at(&mut self, index: usize, value: bool) {
        if let Body::Known { values, .. } = &mut self.body
            && let Some(slot) = values.get_mut(index)
        {
            *slot = Value::Flag(value);
        }
    }

    /// Кладёт значение в поле по имени.
    ///
    /// Так заполняет форму разбор ссылки: там значения приходят строками, а
    /// переключатель — строкой `1`.
    pub fn set_text(&mut self, key: &'static str, value: String) {
        let Some(index) = self.spec().and_then(|spec| spec.index_of(key)) else {
            return;
        };
        let flag = self
            .fields()
            .get(index)
            .is_some_and(|field| field.is_flag());

        if flag {
            self.toggle_at(index, matches!(value.as_str(), "1" | "true" | "yes" | "on"));
        } else {
            self.set_at(index, value);
        }
    }

    /// Значение поля по имени.
    fn at(&self, key: &str) -> Option<&Value> {
        let index = self.spec()?.index_of(key)?;
        match &self.body {
            Body::Known { values, .. } => values.get(index),
            Body::Foreign { .. } => None,
        }
    }

    /// Собирает профиль.
    ///
    /// `Err` — текст, который можно показать как есть: разбирать код ошибки в
    /// интерфейсе всё равно некому.
    pub fn to_profile(&self) -> Result<Profile, String> {
        let outbound = match &self.body {
            Body::Known { spec, values } => RawOutbound::new(spec.id, params(spec, values)?),
            // Чужие параметры не трогаются вовсе: окно не знает, что в них
            // обязательно, а что нет, и «прибрать» их значило бы сломать
            // профиль правкой имени.
            Body::Foreign { protocol, params } => RawOutbound::new(protocol, params.clone()),
        };

        let name = match self.name.trim() {
            // Безымянный профиль неотличим в списке от соседнего; адрес
            // сервера — единственное, что про него точно известно.
            "" => fallback_name(&outbound),
            name => name.to_owned(),
        };
        let id = self.id.clone().unwrap_or_else(|| slug(&name));

        Ok(Profile::new(ProfileId::new(id), name, outbound))
    }
}

/// Пустое значение поля.
fn blank(field: &FieldSpec) -> Value {
    if field.is_flag() {
        Value::Flag(field.default_on)
    } else {
        // У поля выбора пусто не бывает: пустой список в форме обещает выбор,
        // которого в нём нет. У остальных `default_text` — пустая строка, и
        // поведение не меняется.
        Value::Text(field.default_text().to_owned())
    }
}

/// Читает значение поля из параметров профиля.
fn read(field: &FieldSpec, params: &serde_json::Value) -> Value {
    let found = std::iter::once(field.path)
        .chain(field.also.iter().copied())
        .find_map(|path| at_path(params, path));

    if field.is_flag() {
        // Нет в настройках — значит, стоит умолчание протокола. Прочитать это
        // как «выключено» значило бы показать снятый флажок там, где на самом
        // деле всё работает.
        Value::Flag(found.map_or(field.default_on, |value| {
            value.as_bool().unwrap_or(field.default_on)
        }))
    } else {
        let text = found.and_then(as_text).unwrap_or_default();
        // Профиль, где поля нет, открывается на умолчании протокола, а не
        // пустым: пустой выбор человек прочитает как поломку формы.
        if text.is_empty() {
            return Value::Text(field.default_text().to_owned());
        }
        Value::Text(text)
    }
}

/// Значение по пути внутри параметров.
fn at_path<'a>(params: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    let mut current = params;
    for step in path {
        current = current.get(step)?;
    }
    Some(current)
}

/// Значение строкой — как его показывать в поле.
///
/// Числа тоже: полосу пишут и `"100 mbps"`, и просто `100`, а поле в форме
/// одно, и увидеть в нём пустоту вместо своего числа человек не должен.
fn as_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Складывает параметры протокола из набранного.
///
/// Незаполненное поле **пропускается**, а не пишется пустым. Разница не
/// косметическая: настройки лежат в TOML, а в нём пустого значения не
/// существует вовсе. `serde_json::Value::Null` сериализуется как «единица», и
/// `toml` отвечает `unsupported unit type` — профиль перестаёт сохраняться
/// целиком, причём молча для того, кто просто не заполнил необязательное поле.
fn params(spec: &ProtocolSpec, values: &[Value]) -> Result<serde_json::Value, String> {
    let mut out = serde_json::Map::new();

    for (field, value) in spec.fields.iter().zip(values) {
        match value {
            Value::Flag(on) => {
                // Пишется, только когда отличается от умолчания: так файл
                // остаётся коротким, а прочитанное совпадает с записанным.
                if *on != field.default_on {
                    put(&mut out, field.path, serde_json::Value::Bool(*on));
                }
            }
            Value::Text(text) => {
                let text = text.trim();
                if text.is_empty() {
                    if let Some(missing) = field.required {
                        return Err(missing(crate::i18n::s()).to_owned());
                    }
                    continue;
                }
                if let Some(check) = field.check {
                    check(text)?;
                }

                put(
                    &mut out,
                    field.path,
                    serde_json::Value::String(text.to_owned()),
                );
                for (path, constant) in field.with {
                    put(
                        &mut out,
                        path,
                        serde_json::Value::String((*constant).to_owned()),
                    );
                }
            }
        }
    }

    Ok(serde_json::Value::Object(out))
}

/// Кладёт значение по пути, заводя по дороге вложенные объекты.
///
/// Группа, у которой не осталось ни одного поля, не заводится вовсе: пустой
/// `tls` в файле выглядит как настройка, которую кто-то трогал.
fn put(
    out: &mut serde_json::Map<String, serde_json::Value>,
    path: &[&str],
    value: serde_json::Value,
) {
    let Some((last, groups)) = path.split_last() else {
        return;
    };

    let mut current = out;
    for group in groups {
        let entry = current
            .entry((*group).to_owned())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

        match entry.as_object_mut() {
            Some(nested) => current = nested,
            // Место занято не объектом. Такого не бывает: пути описаны
            // константами, и пересечься они могут только опечаткой в
            // описании. Уронить из-за неё окно нельзя — поле просто не
            // запишется, и это увидит тест протокола.
            None => return,
        }
    }
    current.insert((*last).to_owned(), value);
}

/// Имя, которым назвать профиль, если его не назвали.
fn fallback_name(outbound: &RawOutbound) -> String {
    outbound
        .field("server")
        .and_then(|value| value.as_str())
        .map_or_else(|| outbound.protocol.clone(), str::to_owned)
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
    use serde_json::json;

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

    fn draft() -> Draft {
        let mut draft = Draft::new(protocol::by_id("hysteria2").expect("протокол есть"));
        draft.name = "Дом".to_owned();
        draft.set_text("server", "example.com:443".to_owned());
        draft.set_text("password", "секрет".to_owned());
        draft
    }

    fn socks() -> Draft {
        let mut draft = Draft::new(protocol::by_id("socks5").expect("протокол есть"));
        draft.name = "Локальный".to_owned();
        draft.set_text("server", "127.0.0.1:1080".to_owned());
        draft
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

    /// Годное значение для обязательного поля по его имени.
    ///
    /// Таблица, а не выдумка на месте: у поля бывает проверка, и случайная
    /// строка её не пройдёт. Пустая строка означает «образца нет» — и тест
    /// ниже на этом падает, чтобы новый протокол с новым обязательным полем
    /// не проехал молча.
    fn sample(key: &str) -> &'static str {
        match key {
            "server" => "example.com:443",
            "password" => "секрет",
            "uuid" => "b831381d-6324-4d53-ad4f-8cda48b30811",
            "psk" => "общий ключ",
            _ => "",
        }
    }

    #[test]
    fn every_protocol_makes_a_profile_of_its_own_name() {
        // Иначе выбор протокола ничего не решает: сохранится всё равно первый.
        for spec in protocol::ALL {
            let mut draft = Draft::new(spec);

            for field in spec.fields {
                if field.required.is_none() || field.is_flag() {
                    continue;
                }
                // Поле выбора заполнено умолчанием из описания.
                if field.is_choice() {
                    continue;
                }
                let value = sample(field.key);
                assert!(
                    !value.is_empty(),
                    "`{}`: обязательное поле `{}` без образца — допишите его в `sample`",
                    spec.id,
                    field.key
                );
                draft.set_text(field.key, value.to_owned());
            }

            let profile = draft.to_profile().expect("профиль собирается");
            assert_eq!(profile.outbound.protocol, spec.id);
        }
    }

    #[test]
    fn an_unfilled_field_is_left_out_not_written_empty() {
        // Настройки лежат в TOML, а пустого значения в нём не существует.
        // Раньше «не заполнил SNI, но снял проверку сертификата» давало
        // `sni: null`, и профиль переставал сохраняться — с сообщением
        // `unsupported unit type`, из которого понять ничего нельзя.
        let mut draft = draft();
        draft.set_text("insecure", "1".to_owned());

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
        let mut draft = draft();
        draft.set_text("down", "100 mbps".to_owned());

        let profile = draft.to_profile().expect("профиль собирается");
        assert!(!has_null(&profile.outbound.params));
        assert_eq!(
            profile
                .outbound
                .field("bandwidth")
                .and_then(|group| group.get("up")),
            None
        );
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
    fn a_companion_value_comes_with_its_field() {
        // Пароль обфускации без типа не значит ничего, а спрашивать тип не о
        // чем: Salamander — единственный, какой есть.
        let mut draft = draft();
        draft.set_text("obfs", "соль".to_owned());

        let profile = draft.to_profile().expect("профиль собирается");
        assert_eq!(
            profile
                .outbound
                .field("obfs")
                .and_then(|group| group.get("type"))
                .and_then(|value| value.as_str()),
            Some("salamander")
        );
    }

    #[test]
    fn filled_fields_are_written_and_read_back() {
        let mut draft = draft();
        for (key, value) in [
            ("sni", "cdn.example.com"),
            ("obfs", "соль"),
            ("up", "50 mbps"),
            ("down", "200 mbps"),
        ] {
            draft.set_text(key, value.to_owned());
        }
        draft.set_text("insecure", "1".to_owned());

        let profile = draft.to_profile().expect("профиль собирается");
        let back = Draft::from_profile(&profile);

        // Правка имени не должна стирать всё остальное.
        assert_eq!(back.text("sni"), "cdn.example.com");
        assert_eq!(back.text("obfs"), "соль");
        assert_eq!(back.text("up"), "50 mbps");
        assert_eq!(back.text("down"), "200 mbps");
        assert!(back.flag("insecure"));
        assert_eq!(back.text("password"), "секрет");
    }

    #[test]
    fn a_flag_that_is_on_by_default_survives_the_round_trip() {
        // UDP у SOCKS5 включён и в форме, и в самом протоколе. Записать его
        // как есть и прочитать обратно надо одинаково, иначе флажок в окне
        // покажет не то, что происходит.
        let profile = socks().to_profile().expect("профиль собирается");
        assert!(
            profile.outbound.field("udp").is_none(),
            "умолчание попало в файл"
        );
        assert!(Draft::from_profile(&profile).flag("udp"));

        let mut off = socks();
        off.set_text("udp", "0".to_owned());
        let profile = off.to_profile().expect("профиль собирается");
        assert_eq!(
            profile.outbound.field("udp").and_then(|v| v.as_bool()),
            Some(false),
            "выключенный UDP обязан попасть в файл"
        );
        assert!(!Draft::from_profile(&profile).flag("udp"));
    }

    #[test]
    fn a_field_reads_from_its_other_name_too() {
        // Конфигурацию приносят от провайдера как есть: у Hysteria 2 пароль
        // зовётся то `password`, то `auth`.
        let profile = Profile::new(
            "home",
            "Дом",
            RawOutbound::new(
                "hysteria2",
                json!({ "server": "example.com:443", "auth": "секрет" }),
            ),
        );
        assert_eq!(Draft::from_profile(&profile).text("password"), "секрет");
    }

    #[test]
    fn a_broken_address_is_reported_before_saving() {
        // Профиль, который сохраняется, но не подключается, — худший исход:
        // виновата будет «служба».
        let mut draft = draft();
        draft.set_text("server", "просто-текст".to_owned());
        assert!(draft.to_profile().is_err());
    }

    #[test]
    fn a_missing_required_field_is_named() {
        let mut without_password = draft();
        without_password.set_text("password", "   ".to_owned());
        assert_eq!(
            without_password.to_profile().expect_err("не собирается"),
            crate::i18n::s().need_password
        );

        let mut without_server = draft();
        without_server.set_text("server", String::new());
        assert_eq!(
            without_server.to_profile().expect_err("не собирается"),
            crate::i18n::s().need_server
        );
    }

    #[test]
    fn a_proxy_needs_neither_name_nor_password() {
        // Прокси без пароля — обычное дело: `ssh -D` поднимает именно такой.
        let profile = socks().to_profile().expect("профиль собирается");
        assert!(profile.outbound.field("username").is_none());
        assert!(profile.outbound.field("password").is_none());
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
    fn a_nameless_profile_is_named_by_its_address() {
        let mut draft = draft();
        draft.name = String::new();
        assert_eq!(
            draft.to_profile().expect("собирается").name,
            "example.com:443"
        );
    }

    #[test]
    fn slugs_are_usable_identifiers() {
        assert_eq!(slug("Дом"), "дом");
        assert_eq!(slug("Server #1 (RU)"), "server--1--ru");
        assert_eq!(slug("   "), "profile");
        assert_eq!(slug("---"), "profile");
    }

    #[test]
    fn every_field_round_trips_through_the_form() {
        // Поле, которое читается не оттуда, куда пишется, — это поле, которое
        // молча теряет введённое.
        for spec in protocol::ALL {
            let mut draft = Draft::new(spec);
            for (index, field) in spec.fields.iter().enumerate() {
                if field.is_flag() {
                    draft.toggle_at(index, !field.default_on);
                } else {
                    draft.set_at(index, field.key.to_owned());
                }
            }

            for field in spec.fields {
                if field.is_flag() {
                    assert_eq!(draft.flag(field.key), !field.default_on, "{}", field.key);
                } else {
                    assert_eq!(draft.text(field.key), field.key, "{}", field.key);
                }
            }
        }
    }

    #[test]
    fn a_message_for_a_field_that_is_gone_is_ignored() {
        // Сообщение о правке могло уехать до смены протокола: паниковать из-за
        // этого нельзя, а молча писать не в то поле — тем более.
        let mut draft = draft();
        draft.set_at(99, "мимо".to_owned());
        draft.toggle_at(99, true);
        draft.to_profile().expect("профиль цел");
    }

    #[test]
    fn an_unknown_protocol_keeps_its_settings() {
        // Настройки мог написать человек или прислать новая версия. Правка
        // имени не должна стирать то, чего окно не понимает.
        let params = json!({ "server": "example.com:443", "reality": { "key": "x" } });
        let profile = Profile::new("x", "Чужой", RawOutbound::new("телепатия", params.clone()));

        let mut draft = Draft::from_profile(&profile);
        assert!(draft.spec().is_none(), "протокол не должен опознаться");
        assert!(draft.fields().is_empty(), "полей у него быть не может");
        draft.name = "Переименован".to_owned();

        let saved = draft.to_profile().expect("профиль собирается");
        assert_eq!(saved.name, "Переименован");
        assert_eq!(saved.outbound.protocol, "телепатия");
        assert_eq!(saved.outbound.params, params);
    }

    #[test]
    fn a_number_in_the_settings_shows_up_in_the_field() {
        // Полосу пишут и `"100 mbps"`, и просто числом; пустое поле на месте
        // своего числа человек прочитает как потерю настройки.
        let profile = Profile::new(
            "home",
            "Дом",
            RawOutbound::new(
                "hysteria2",
                json!({ "server": "e.com:443", "auth": "x", "bandwidth": { "up": 100 } }),
            ),
        );
        assert_eq!(Draft::from_profile(&profile).text("up"), "100");
    }
}
