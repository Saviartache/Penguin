//! Черновик группы: что отмечено и во что это превращается.
//!
//! Три раздела — приложения, адреса, порты — означают «и» (этот сайт у этого
//! приложения; «или» утащило бы весь трафик приложения), внутри раздела — «или».
//! Пустой раздел — «любые».

use penguin_config::schema::rule::{Condition, Leaf, RuleAction, RuleConfig};

use crate::forms::addresses::{self, Kind};

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

/// Раздел группы; разделы значат «и», значения внутри раздела — «или».
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Section {
    /// Приложения.
    #[default]
    Apps,
    /// Домены, адреса и подсети.
    Hosts,
    /// Порты и диапазоны.
    Ports,
}

impl Section {
    /// Все разделы в порядке показа.
    pub const ALL: [Self; 3] = [Self::Apps, Self::Hosts, Self::Ports];
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
    /// Домены, адреса и подсети — каждое значение проверено при добавлении.
    pub hosts: Vec<String>,
    /// Порты и диапазоны (`443`, `27000-27100`).
    pub ports: Vec<String>,
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

    /// Значения раздела.
    pub fn values(&self, section: Section) -> &[String] {
        match section {
            Section::Apps => &self.processes,
            Section::Hosts => &self.hosts,
            Section::Ports => &self.ports,
        }
    }

    /// Раскладывает введённое по разделам: адрес — в адреса, порт — в порты,
    /// `host:443` — в оба. Возвращает непонятое — оно остаётся в поле, чтобы его
    /// поправили, а не потеряли.
    pub fn add(&mut self, raw: &str) -> String {
        let mut rest = Vec::new();
        for token in addresses::tokens(raw) {
            // `=точный.домен` и `*слово*` — только адреса, порта у них нет.
            if token.starts_with(['=', '*']) {
                match host_kind(token) {
                    Some(_) => push_new(&mut self.hosts, token.to_ascii_lowercase()),
                    None => rest.push(token),
                }
                continue;
            }
            let (host, port) = match addresses::split_port(token) {
                Some((host, port)) => (Some(host), Some(port)),
                None => match addresses::classify(token) {
                    Some(Kind::Port) => (None, Some(token)),
                    Some(_) => (Some(token), None),
                    None => (None, None),
                },
            };
            let host_ok = host.is_none_or(|host| {
                matches!(
                    addresses::classify(host),
                    Some(Kind::Domain | Kind::Network)
                )
            });
            let port_ok = port.is_none_or(|port| addresses::parse(port).unknown.is_empty());
            if (host.is_none() && port.is_none()) || !host_ok || !port_ok {
                rest.push(token);
                continue;
            }
            if let Some(host) = host {
                push_new(&mut self.hosts, host.to_ascii_lowercase());
            }
            if let Some(port) = port {
                push_new(&mut self.ports, port.to_owned());
            }
        }
        rest.join(", ")
    }

    /// Убирает значение из адресов или портов.
    pub fn remove(&mut self, value: &str) {
        self.hosts.retain(|known| known != value);
        self.ports.retain(|known| known != value);
    }

    /// Есть ли что сохранять.
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty() && self.hosts.is_empty() && self.ports.is_empty()
    }

    /// Собирает правило; `None` — условий нет, а такое совпало бы со всем.
    pub fn build(&self, id: impl Into<String>) -> Option<RuleConfig> {
        let mut apps = Vec::new();
        if !self.processes.is_empty() {
            apps.push(Leaf::ProcessPath(self.processes.clone()));
        }

        // Значения проверены при добавлении; вид каждого — по записи.
        let mut by_kind: [Vec<String>; 4] = Default::default();
        for host in &self.hosts {
            if let Some((kind, value)) = host_kind(host) {
                by_kind[kind as usize].push(value.to_owned());
            }
        }
        let [suffix, exact, keyword, network] = by_kind;
        let hosts: Vec<Leaf> = [
            Leaf::DomainSuffix(suffix),
            Leaf::Domain(exact),
            Leaf::DomainKeyword(keyword),
            Leaf::DestIp(network),
        ]
        .into_iter()
        .filter(|leaf| !leaf_is_empty(leaf))
        .collect();

        let parsed = addresses::parse(&self.ports.join(" "));
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

/// Вид записи в разделе адресов. Порядок — номер в раскладке [`Draft::build`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    /// `example.com` — домен и поддомены.
    Suffix,
    /// `=example.com` — только этот домен.
    Exact,
    /// `*word*` — домен, в котором есть слово.
    Keyword,
    /// Адрес или подсеть.
    Network,
}

/// Вид записи и значение без пометок; `None` — не адрес.
pub fn host_kind(value: &str) -> Option<(HostKind, &str)> {
    if let Some(name) = value.strip_prefix('=') {
        return (addresses::classify(name) == Some(Kind::Domain))
            .then_some((HostKind::Exact, name));
    }
    if let Some(word) = value
        .strip_prefix('*')
        .and_then(|rest| rest.strip_suffix('*'))
    {
        let valid = !word.is_empty()
            && word
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '.');
        return valid.then_some((HostKind::Keyword, word));
    }
    match addresses::classify(value) {
        Some(Kind::Domain) => Some((HostKind::Suffix, value)),
        Some(Kind::Network) => Some((HostKind::Network, value)),
        _ => None,
    }
}

fn leaf_is_empty(leaf: &Leaf) -> bool {
    match leaf {
        Leaf::DomainSuffix(values)
        | Leaf::Domain(values)
        | Leaf::DomainKeyword(values)
        | Leaf::DestIp(values) => values.is_empty(),
        _ => false,
    }
}

/// Дописывает значение, если его ещё нет.
fn push_new(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
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
        draft.add("steamcontent.com");

        let rule = draft.build("r1").expect("правило собирается");
        let Condition::All { all } = rule.when else {
            panic!("разделы обязаны означать «и»");
        };
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn a_domain_and_a_subnet_mean_or() {
        let mut draft = draft();
        draft.add("youtube.com 10.0.0.0/8");

        let rule = draft.build("r1").expect("правило собирается");
        let Condition::Any { any } = rule.when else {
            panic!("домен и подсеть одной группы обязаны означать «или»");
        };
        assert_eq!(any.len(), 2);
    }

    #[test]
    fn a_port_range_is_kept_whole() {
        let mut draft = draft();
        draft.add("27000-27100");

        let rule = draft.build("r1").expect("правило собирается");
        assert_eq!(
            rule.when,
            Condition::Leaf(Leaf::DestPortRange(vec![(27000, 27100)]))
        );
    }

    #[test]
    fn typed_values_land_in_their_sections() {
        let mut draft = draft();
        let rest = draft.add("Google.com, 10.0.0.0/8; 443 192.168.1.0:30000 ??? 500-100");

        assert_eq!(draft.hosts, ["google.com", "10.0.0.0/8", "192.168.1.0"]);
        assert_eq!(draft.ports, ["443", "30000"]);
        assert_eq!(rest, "???, 500-100", "непонятое остаётся в поле");

        // Повтор не дублирует.
        assert_eq!(draft.add("google.com 443"), "");
        assert_eq!(draft.hosts.len(), 3);
        assert_eq!(draft.ports.len(), 2);
    }

    #[test]
    fn marks_choose_the_kind_of_domain() {
        let mut draft = draft();
        assert_eq!(draft.add("=Copilot.com *google* =nope *a.b"), "=nope, *a.b");
        assert_eq!(draft.hosts, ["=copilot.com", "*google*"]);
        assert_eq!(
            host_kind("=copilot.com"),
            Some((HostKind::Exact, "copilot.com"))
        );
        assert_eq!(host_kind("*google*"), Some((HostKind::Keyword, "google")));
        assert_eq!(host_kind("*google"), None);

        let rule = draft.build("r1").expect("собирается");
        assert_eq!(
            rule.when,
            Condition::Any {
                any: vec![
                    Condition::Leaf(Leaf::Domain(vec!["copilot.com".to_owned()])),
                    Condition::Leaf(Leaf::DomainKeyword(vec!["google".to_owned()])),
                ]
            }
        );
    }

    #[test]
    fn a_value_is_removed_from_its_section() {
        let mut draft = draft();
        draft.add("example.com 443");
        draft.remove("443");
        assert!(draft.ports.is_empty());
        assert_eq!(draft.values(Section::Hosts), ["example.com"]);
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
            hosts: vec!["example.com".to_owned()],
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
        draft.add("example.com 443");

        let rule = draft.build("r1").expect("правило собирается");
        let json = serde_json::to_string(&rule).expect("сериализуется");
        let back: RuleConfig = serde_json::from_str(&json).expect("разбирается");
        assert_eq!(back, rule);
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
