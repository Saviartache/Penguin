//! Сериализуемая форма правила: условия и действие.
//!
//! Условие — дерево, а не плоский список полей. Плоский список («приложение И
//! адрес И порт») выражает только конъюнкцию, и первое же настоящее желание
//! пользователя — «Chrome и Firefox напрямую, но их обращения к банку — в
//! тоннель» — в нём уже не записывается. Дерево из `all` / `any` / `not` над
//! листьями-условиями записывает это буквально и не требует новых полей.
//!
//! ```toml
//! [[routing.rules]]
//! id     = "bank"
//! name   = "Банк всегда через тоннель"
//! action = "tunnel"
//! [routing.rules.when]
//! all = [
//!   { process_name = ["chrome.exe", "firefox.exe"] },
//!   { domain_suffix = ["sberbank.ru", "tinkoff.ru"] },
//! ]
//! ```
//!
//! Пример проверяется тестом (`the_documented_example_parses`): пример,
//! который не разбирается, хуже отсутствующего — по нему пишут файл и получают
//! отказ там, где ошибки не делали.

use serde::{Deserialize, Serialize};

/// Правило маршрутизации.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Устойчивый идентификатор. Порядок в файле меняется, ссылки — нет.
    pub id: String,
    /// Имя для интерфейса.
    #[serde(default)]
    pub name: String,
    /// Выключенное правило остаётся в файле, но не участвует в разборе.
    /// Это и есть «попробовать без него», не удаляя настройку.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Чем меньше число, тем раньше проверяется правило.
    #[serde(default)]
    pub priority: i32,
    /// Условие.
    pub when: Condition,
    /// Что делать при совпадении.
    pub action: RuleAction,
}

/// Действие правила.
///
/// В файле пишется двумя способами, и оба обязаны работать:
///
/// ```toml
/// action = "tunnel"                        # в активный профиль
/// action = { tunnel = { profile = "office" } }   # в конкретный
/// ```
///
/// Первый — тот, который человек пишет в девяти случаях из десяти. Без него
/// «в тоннель» нельзя было бы записать так же коротко, как «напрямую», хотя
/// это ровно такое же однословное решение. Перевод между записью в файле и
/// этим перечислением — [`ActionRepr`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(from = "ActionRepr", into = "ActionRepr")]
pub enum RuleAction {
    /// В тоннель. Без указания профиля — в активный.
    Tunnel {
        /// Конкретный профиль, если нужен не активный.
        profile: Option<String>,
    },
    /// Мимо тоннеля.
    Direct,
    /// Оборвать соединение.
    Block,
}

/// Как действие выглядит в файле.
///
/// `untagged`: сначала пробуется короткая запись словом, потом подробная.
/// Порядок важен — `"tunnel"` обязан читаться как действие без профиля, а не
/// как ошибка разбора подробной формы.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ActionRepr {
    /// `action = "tunnel"`.
    Bare(BareAction),
    /// `action = { tunnel = { profile = "office" } }`.
    Detailed(DetailedAction),
}

/// Действие одним словом.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BareAction {
    /// В активный профиль.
    Tunnel,
    /// Мимо тоннеля.
    Direct,
    /// Оборвать соединение.
    Block,
}

/// Действие с уточнением.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetailedAction {
    /// В названный профиль.
    Tunnel {
        /// Какой именно профиль.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile: Option<String>,
    },
}

impl From<ActionRepr> for RuleAction {
    fn from(repr: ActionRepr) -> Self {
        match repr {
            ActionRepr::Bare(BareAction::Tunnel) => Self::Tunnel { profile: None },
            ActionRepr::Bare(BareAction::Direct) => Self::Direct,
            ActionRepr::Bare(BareAction::Block) => Self::Block,
            ActionRepr::Detailed(DetailedAction::Tunnel { profile }) => Self::Tunnel { profile },
        }
    }
}

impl From<RuleAction> for ActionRepr {
    fn from(action: RuleAction) -> Self {
        match action {
            // Без профиля — короткой записью: файл, перезаписанный клиентом,
            // должен читаться так же, как написанный руками.
            RuleAction::Tunnel { profile: None } => Self::Bare(BareAction::Tunnel),
            RuleAction::Tunnel { profile } => Self::Detailed(DetailedAction::Tunnel { profile }),
            RuleAction::Direct => Self::Bare(BareAction::Direct),
            RuleAction::Block => Self::Bare(BareAction::Block),
        }
    }
}

/// Условие: лист или узел.
///
/// `untagged` ради читаемого файла: в TOML и JSON условие выглядит как
/// объект с одним понятным ключом, без служебной обёртки `{ "type": ... }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Condition {
    /// Все вложенные условия должны совпасть.
    All {
        /// Вложенные условия.
        all: Vec<Condition>,
    },
    /// Достаточно одного совпадения.
    Any {
        /// Вложенные условия.
        any: Vec<Condition>,
    },
    /// Отрицание.
    Not {
        /// Вложенное условие.
        not: Box<Condition>,
    },
    /// Лист.
    Leaf(Leaf),
}

/// Элементарное условие.
///
/// Каждый вариант — отдельный ключ в файле. Списки, а не одиночные значения:
/// «пять браузеров напрямую» — одно правило, а не пять.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Leaf {
    /// Полный путь к исполняемому файлу. Регистр и разделители нормализуются.
    ProcessPath(Vec<String>),
    /// Имя исполняемого файла без пути.
    ProcessName(Vec<String>),
    /// Шаблон пути: `C:/Games/**/*.exe`.
    ProcessPathGlob(Vec<String>),

    /// Точное совпадение домена.
    Domain(Vec<String>),
    /// Домен и все поддомены.
    DomainSuffix(Vec<String>),
    /// Подстрока в домене.
    DomainKeyword(Vec<String>),
    /// Регулярное выражение по домену.
    DomainRegex(Vec<String>),

    /// Адрес или подсеть назначения в записи CIDR.
    DestIp(Vec<String>),
    /// Порт назначения.
    DestPort(Vec<u16>),
    /// Диапазон портов назначения, включительно.
    DestPortRange(Vec<(u16, u16)>),

    /// Страна по базе GeoIP: `["RU", "BY"]`.
    GeoIp(Vec<String>),
    /// Готовый набор доменов: `["category-ads", "private"]`.
    GeoSite(Vec<String>),

    /// Вид трафика: `["tcp"]`, `["udp"]`.
    Network(Vec<String>),
    /// Версия протокола сети: `["v4"]`, `["v6"]`.
    IpVersion(Vec<String>),
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Разбирает правило из TOML — так, как его пишет человек.
    fn from_toml(raw: &str) -> RuleConfig {
        toml::from_str(raw).expect("правило разбирается")
    }

    #[test]
    fn the_documented_short_form_works() {
        // Запись из шапки файла и из README. Если она не разбирается,
        // документация врёт ровно в самом частом месте.
        let rule = from_toml(
            r#"
            id = "r1"
            action = "tunnel"
            [when]
            domain_suffix = ["example.com"]
            "#,
        );
        assert_eq!(rule.action, RuleAction::Tunnel { profile: None });
    }

    #[test]
    fn every_action_has_a_short_form() {
        for (written, expected) in [
            ("tunnel", RuleAction::Tunnel { profile: None }),
            ("direct", RuleAction::Direct),
            ("block", RuleAction::Block),
        ] {
            let rule = from_toml(&format!(
                "id = \"r1\"\naction = \"{written}\"\n[when]\ndest_port = [443]\n"
            ));
            assert_eq!(rule.action, expected, "не разобралось: {written}");
        }
    }

    #[test]
    fn a_named_profile_is_written_the_long_way() {
        let rule = from_toml(
            r#"
            id = "r1"
            action = { tunnel = { profile = "office" } }
            [when]
            dest_port = [443]
            "#,
        );
        assert_eq!(
            rule.action,
            RuleAction::Tunnel {
                profile: Some("office".to_owned())
            }
        );
    }

    #[test]
    fn a_rewritten_file_reads_like_a_handwritten_one() {
        // Клиент перезаписывает файл целиком по «Сохранить». Если он выберет
        // подробную запись там, где хватает короткой, файл начнёт отличаться
        // от того, что человек в него написал, — без единого изменения по
        // смыслу.
        let rule = from_toml(
            "id = \"r1\"
action = \"tunnel\"
[when]
dest_port = [443]
",
        );
        let written = toml::to_string(&rule).expect("сериализуется");

        assert!(
            written.contains("action = \"tunnel\""),
            "записано подробно: {written}"
        );
        assert_eq!(from_toml(&written).action, rule.action);
    }

    #[test]
    fn actions_survive_a_round_trip() {
        for action in [
            RuleAction::Tunnel { profile: None },
            RuleAction::Tunnel {
                profile: Some("office".to_owned()),
            },
            RuleAction::Direct,
            RuleAction::Block,
        ] {
            let json = serde_json::to_string(&action).expect("сериализуется");
            let back: RuleAction = serde_json::from_str(&json).expect("разбирается");
            assert_eq!(back, action, "не пережило JSON: {json}");
        }
    }

    #[test]
    fn the_documented_example_parses() {
        // Ровно то, что написано в шапке этого файла.
        let rule = from_toml(
            r#"
            id     = "bank"
            name   = "Банк всегда через тоннель"
            action = "tunnel"
            [when]
            all = [
              { process_name = ["chrome.exe", "firefox.exe"] },
              { domain_suffix = ["sberbank.ru", "tinkoff.ru"] },
            ]
            "#,
        );
        assert_eq!(rule.action, RuleAction::Tunnel { profile: None });
        assert!(matches!(rule.when, Condition::All { .. }));
    }

    #[test]
    fn a_rule_is_enabled_unless_it_says_otherwise() {
        // Правило, приехавшее выключенным из-за умолчания, выглядит как не
        // сработавшее — и ищут причину не там.
        let rule = from_toml("id = \"r1\"\naction = \"direct\"\n[when]\ndest_port = [443]\n");
        assert!(rule.enabled);
    }
}
