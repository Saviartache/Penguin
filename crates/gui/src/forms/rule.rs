//! Черновик правила: что отмечено и во что это превращается.
//!
//! Тонкость ровно одна, и она смысловая: **что означает несколько условий
//! сразу**.
//!
//! Ответ — «и». Пользователь, отметивший приложение и вписавший домен, имеет в
//! виду «этот домен у этого приложения», а не «этот домен или это приложение».
//! Второе прочтение утащило бы в тоннель весь трафик приложения — и человек
//! узнал бы об этом не скоро.
//!
//! Внутри одного условия — наоборот «или»: пять отмеченных приложений это пять
//! вариантов, а не пять одновременных требований.

use penguin_config::schema::rule::{Condition, Leaf, RuleAction, RuleConfig};

use crate::forms::addresses;

/// Что делает правило.
///
/// Своё перечисление, а не [`RuleAction`]: тому нужен профиль, а выпадающему
/// списку — короткая подпись и `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Action {
    /// Мимо тоннеля.
    #[default]
    Direct,
    /// В тоннель.
    Tunnel,
    /// Оборвать.
    Block,
}

impl Action {
    /// Все действия в порядке показа.
    pub const ALL: [Self; 3] = [Self::Direct, Self::Tunnel, Self::Block];
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Direct => crate::i18n::s().action_direct,
            Self::Tunnel => crate::i18n::s().action_tunnel,
            Self::Block => crate::i18n::s().action_block,
        })
    }
}

impl From<Action> for RuleAction {
    fn from(action: Action) -> Self {
        match action {
            // Без профиля: правило должно пережить смену активного сервера.
            Action::Tunnel => Self::Tunnel { profile: None },
            Action::Direct => Self::Direct,
            Action::Block => Self::Block,
        }
    }
}

/// Что ввёл пользователь.
#[derive(Debug, Clone, Default)]
pub struct Draft {
    /// Имя правила.
    pub name: String,
    /// Отмеченные приложения — полными путями.
    pub processes: Vec<String>,
    /// Адреса, подсети, домены и порты одной строкой.
    pub addresses: String,
    /// Что делать при совпадении.
    pub action: Action,
}

impl Draft {
    /// Отмечено ли приложение.
    pub fn has_process(&self, path: &str) -> bool {
        self.processes.iter().any(|known| known == path)
    }

    /// Отмечает или снимает приложение.
    ///
    /// Список приходит от службы и перерисовывается; двойной щелчок по одной
    /// строке не должен давать два одинаковых пути в правиле.
    pub fn toggle_process(&mut self, path: &str, checked: bool) {
        if checked {
            if !self.has_process(path) {
                self.processes.push(path.to_owned());
            }
        } else {
            self.processes.retain(|known| known != path);
        }
    }

    /// Есть ли что сохранять.
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty() && addresses::parse(&self.addresses).is_empty()
    }

    /// Что из вписанного не удалось опознать.
    ///
    /// Молча выбросить это нельзя: правило соберётся, но не тем, чего ждали, и
    /// разбираться человек будет уже по последствиям.
    pub fn unknown(&self) -> Vec<String> {
        addresses::parse(&self.addresses).unknown
    }

    /// Собирает правило.
    ///
    /// `None` — не задано ни одного условия: правило без условий совпадает со
    /// всем подряд, и сохранять такое молча нельзя.
    pub fn build(&self, id: impl Into<String>) -> Option<RuleConfig> {
        let parsed = addresses::parse(&self.addresses);
        let mut conditions = Vec::new();

        if !self.processes.is_empty() {
            conditions.push(Condition::Leaf(Leaf::ProcessPath(self.processes.clone())));
        }
        if !parsed.domains.is_empty() {
            conditions.push(Condition::Leaf(Leaf::DomainSuffix(parsed.domains)));
        }
        if !parsed.networks.is_empty() {
            conditions.push(Condition::Leaf(Leaf::DestIp(parsed.networks)));
        }
        if !parsed.ports.is_empty() {
            conditions.push(Condition::Leaf(Leaf::DestPort(parsed.ports)));
        }

        let when = match conditions.len() {
            0 => return None,
            // Одно условие не заворачивается в `all`: лишний уровень читался
            // бы в файле как ошибка.
            1 => conditions.remove(0),
            // Несколько условий — «и»: «этот домен у этого приложения».
            _ => Condition::All { all: conditions },
        };

        Some(RuleConfig {
            id: id.into(),
            name: if self.name.trim().is_empty() {
                crate::i18n::s().unnamed_rule.to_owned()
            } else {
                self.name.trim().to_owned()
            },
            // Правило, созданное выключенным, выглядит как не сработавшее.
            enabled: true,
            priority: 0,
            when,
            action: self.action.into(),
        })
    }
}

/// Придумывает идентификатор, которого ещё нет в наборе.
///
/// Два правила с одним идентификатором — это набор, в котором ссылка на
/// правило указывает на два разных, и решает спор порядок в файле.
pub fn unique_id(rules: &[RuleConfig]) -> String {
    let taken = |id: &str| rules.iter().any(|rule| rule.id == id);

    (1..)
        .map(|number| format!("rule-{number}"))
        .find(|candidate| !taken(candidate))
        // Диапазон бесконечен: `find` без совпадения здесь невозможен.
        .unwrap_or_else(|| "rule".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> Draft {
        Draft {
            name: "Проба".to_owned(),
            ..Draft::default()
        }
    }

    #[test]
    fn an_empty_draft_yields_nothing() {
        // Правило без условий совпадает со всем подряд; сохранять такое молча
        // нельзя.
        assert!(draft().build("r1").is_none());
        assert!(draft().is_empty());
    }

    #[test]
    fn a_single_condition_is_not_wrapped() {
        // Лишний уровень `all` читался бы в файле как ошибка.
        let mut draft = draft();
        draft.processes = vec!["c:/steam/steam.exe".to_owned()];

        let rule = draft.build("r1").expect("правило собирается");
        assert!(matches!(rule.when, Condition::Leaf(Leaf::ProcessPath(_))));
    }

    #[test]
    fn several_conditions_mean_and() {
        // «Этот домен у этого приложения», а не «этот домен или это
        // приложение»: второе утащило бы в тоннель весь трафик приложения.
        let mut draft = draft();
        draft.processes = vec!["c:/steam/steam.exe".to_owned()];
        draft.addresses = "steamcontent.com".to_owned();

        let rule = draft.build("r1").expect("правило собирается");
        let Condition::All { all } = rule.when else {
            panic!("несколько условий обязаны означать «и»");
        };
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn toggling_a_process_is_idempotent() {
        let mut draft = draft();
        draft.toggle_process("c:/app.exe", true);
        draft.toggle_process("c:/app.exe", true);
        assert_eq!(draft.processes.len(), 1);

        draft.toggle_process("c:/app.exe", false);
        assert!(draft.processes.is_empty());
    }

    #[test]
    fn a_nameless_rule_still_gets_a_name() {
        // Безымянная строка в списке неотличима от соседней.
        let draft = Draft {
            name: "   ".to_owned(),
            addresses: "example.com".to_owned(),
            ..Draft::default()
        };
        assert!(
            !draft
                .build("r1")
                .expect("собирается")
                .name
                .trim()
                .is_empty()
        );
    }

    #[test]
    fn tunnel_keeps_no_profile() {
        // Правило должно пережить смену активного сервера.
        assert_eq!(
            RuleAction::from(Action::Tunnel),
            RuleAction::Tunnel { profile: None }
        );
    }

    #[test]
    fn a_built_rule_survives_serialization() {
        // Правило уезжает службе через канал управления и ложится в файл.
        let mut draft = draft();
        draft.addresses = "example.com 443".to_owned();

        let rule = draft.build("r1").expect("правило собирается");
        let json = serde_json::to_string(&rule).expect("сериализуется");
        let back: RuleConfig = serde_json::from_str(&json).expect("разбирается");
        assert_eq!(back, rule);
    }

    #[test]
    fn unrecognised_input_is_reported() {
        let mut draft = draft();
        draft.addresses = "example.com ???".to_owned();
        assert_eq!(draft.unknown(), ["???"]);
    }

    #[test]
    fn identifiers_never_collide() {
        let rules: Vec<RuleConfig> = serde_json::from_value(serde_json::json!([
            { "id": "rule-1", "when": { "dest_port": [1] }, "action": "direct" },
            { "id": "rule-3", "when": { "dest_port": [3] }, "action": "direct" }
        ]))
        .expect("правила разбираются");

        assert_eq!(unique_id(&rules), "rule-2");
        assert_eq!(unique_id(&[]), "rule-1");
    }

    #[test]
    fn every_action_has_a_label() {
        for action in Action::ALL {
            assert!(!action.to_string().is_empty());
        }
    }
}
