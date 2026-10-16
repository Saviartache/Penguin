//! Черновик группы: что отмечено и во что это превращается.
//!
//! Три раздела — приложения, адреса, порты — означают «и» (этот сайт у этого
//! приложения; «или» утащило бы весь трафик приложения), внутри раздела — «или».
//! Пустой раздел — «любые».

use penguin_config::schema::rule::{Condition, Leaf, RuleAction, RuleConfig};

use crate::forms::addresses;

/// Что делает группа; свой тип, а не [`RuleAction`]: тому нужен профиль, списку — `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Action {
    /// В тоннель через текущий сервер.
    #[default]
    Tunnel,
    /// Мимо тоннеля.
    Direct,
    /// Оборвать.
    Block,
}

impl Action {
    /// Все действия в порядке показа.
    pub const ALL: [Self; 3] = [Self::Tunnel, Self::Direct, Self::Block];

    /// Подпись на текущем языке.
    pub fn label(self) -> &'static str {
        match self {
            Self::Direct => crate::i18n::s().action_direct,
            Self::Tunnel => crate::i18n::s().action_tunnel,
            Self::Block => crate::i18n::s().action_block,
        }
    }
}

impl From<Action> for RuleAction {
    fn from(action: Action) -> Self {
        match action {
            // Без профиля: группа переживает смену сервера.
            Action::Tunnel => Self::Tunnel { profile: None },
            Action::Direct => Self::Direct,
            Action::Block => Self::Block,
        }
    }
}

/// Что ввёл пользователь.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Draft {
    /// Место правки в наборе; `None` — новая группа.
    pub index: Option<usize>,
    /// Имя группы.
    pub name: String,
    /// Отмеченные приложения — полными путями.
    pub processes: Vec<String>,
    /// Домены, адреса и подсети одной строкой.
    pub hosts: String,
    /// Порты и диапазоны одной строкой.
    pub ports: String,
    /// Что делать при совпадении.
    pub action: Action,
}

impl Draft {
    /// Отмечено ли приложение.
    pub fn has_process(&self, path: &str) -> bool {
        self.processes.iter().any(|known| known == path)
    }

    /// Отмечает или снимает приложение; повтор не дублирует путь.
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
        self.processes.is_empty() && self.parsed().is_empty()
    }

    /// Что из вписанного не опознано; молча выбросить нельзя.
    pub fn unknown(&self) -> Vec<String> {
        self.parsed().unknown
    }

    /// Оба поля разом: порт в строке адресов понятен и там.
    fn parsed(&self) -> addresses::Parsed {
        addresses::parse(&format!("{} {}", self.hosts, self.ports))
    }

    /// Собирает правило; `None` — условий нет, а такое совпало бы со всем.
    pub fn build(&self, id: impl Into<String>) -> Option<RuleConfig> {
        let parsed = self.parsed();
        let mut apps = Vec::new();
        if !self.processes.is_empty() {
            apps.push(Leaf::ProcessPath(self.processes.clone()));
        }

        let mut hosts = Vec::new();
        if !parsed.domains.is_empty() {
            hosts.push(Leaf::DomainSuffix(parsed.domains));
        }
        if !parsed.networks.is_empty() {
            hosts.push(Leaf::DestIp(parsed.networks));
        }

        let mut ports = Vec::new();
        if !parsed.ports.is_empty() {
            ports.push(Leaf::DestPort(parsed.ports));
        }
        if !parsed.ranges.is_empty() {
            ports.push(Leaf::DestPortRange(parsed.ranges));
        }

        let mut sections: Vec<Condition> = [apps, hosts, ports]
            .into_iter()
            .filter_map(any_of)
            .collect();
        let when = match sections.len() {
            0 => return None,
            1 => sections.remove(0),
            _ => Condition::All { all: sections },
        };

        Some(RuleConfig {
            id: id.into(),
            name: if self.name.trim().is_empty() {
                crate::i18n::s().unnamed_rule.to_owned()
            } else {
                self.name.trim().to_owned()
            },
            // Выключенная с рождения группа выглядит несработавшей.
            enabled: true,
            priority: 0,
            when,
            action: self.action.into(),
        })
    }
}

/// Раздел из листьев: один — как есть, несколько — «или».
fn any_of(mut leaves: Vec<Leaf>) -> Option<Condition> {
    match leaves.len() {
        0 => None,
        1 => Some(Condition::Leaf(leaves.remove(0))),
        _ => Some(Condition::Any {
            any: leaves.into_iter().map(Condition::Leaf).collect(),
        }),
    }
}

/// Придумывает идентификатор, которого нет в наборе.
pub fn unique_id(rules: &[RuleConfig]) -> String {
    let taken = |id: &str| rules.iter().any(|rule| rule.id == id);

    (1..)
        .map(|number| format!("rule-{number}"))
        .find(|candidate| !taken(candidate))
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
        assert!(draft().build("r1").is_none());
        assert!(draft().is_empty());
    }

    #[test]
    fn a_single_condition_is_not_wrapped() {
        let mut draft = draft();
        draft.processes = vec!["c:/steam/steam.exe".to_owned()];

        let rule = draft.build("r1").expect("правило собирается");
        assert!(matches!(rule.when, Condition::Leaf(Leaf::ProcessPath(_))));
    }

    #[test]
    fn sections_mean_and() {
        let mut draft = draft();
        draft.processes = vec!["c:/steam/steam.exe".to_owned()];
        draft.hosts = "steamcontent.com".to_owned();

        let rule = draft.build("r1").expect("правило собирается");
        let Condition::All { all } = rule.when else {
            panic!("разделы обязаны означать «и»");
        };
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn a_domain_and_a_subnet_mean_or() {
        let mut draft = draft();
        draft.hosts = "youtube.com 10.0.0.0/8".to_owned();

        let rule = draft.build("r1").expect("правило собирается");
        let Condition::Any { any } = rule.when else {
            panic!("домен и подсеть одной группы обязаны означать «или»");
        };
        assert_eq!(any.len(), 2);
    }

    #[test]
    fn a_port_range_is_kept_whole() {
        let mut draft = draft();
        draft.ports = "27000-27100".to_owned();

        let rule = draft.build("r1").expect("правило собирается");
        assert_eq!(
            rule.when,
            Condition::Leaf(Leaf::DestPortRange(vec![(27000, 27100)]))
        );
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
        let draft = Draft {
            name: "   ".to_owned(),
            hosts: "example.com".to_owned(),
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
        assert_eq!(
            RuleAction::from(Action::Tunnel),
            RuleAction::Tunnel { profile: None }
        );
    }

    #[test]
    fn a_built_rule_survives_serialization() {
        let mut draft = draft();
        draft.hosts = "example.com".to_owned();
        draft.ports = "443".to_owned();

        let rule = draft.build("r1").expect("правило собирается");
        let json = serde_json::to_string(&rule).expect("сериализуется");
        let back: RuleConfig = serde_json::from_str(&json).expect("разбирается");
        assert_eq!(back, rule);
    }

    #[test]
    fn unrecognised_input_is_reported() {
        let mut draft = draft();
        draft.hosts = "example.com ???".to_owned();
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
            assert!(!action.label().is_empty());
        }
    }
}
