//! Правило из строки журнала: соединение, что из него ловить и куда вписать.
//!
//! Вписать можно только туда, где добавленное **расширяет** группу. Разделы
//! группы значат «и»: адрес, дописанный в группу без адресов, превратил бы «всё
//! от приложения» в «приложение, но только к этому адресу».

use penguin_config::schema::rule::RuleConfig;

use crate::forms::addresses::{self, Kind};
use crate::forms::rule::{self, Action, Draft};

/// Соединение, о котором служба сообщила решение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    /// Куда шло: `хост:порт`.
    pub target: String,
    /// Имя приложения.
    pub process: Option<String>,
    /// Полный путь к нему.
    pub process_path: Option<String>,
    /// Решение словом службы: `direct`, `block`, `proxy[профиль]`.
    pub decision: String,
    /// Сработавшее правило.
    pub rule: Option<String>,
}

impl Flow {
    /// Хост без порта; у IPv6 — без скобок.
    pub fn host(&self) -> &str {
        let target = self.target.as_str();
        if let Some(rest) = target.strip_prefix('[') {
            return rest.split_once(']').map_or(rest, |(host, _)| host);
        }
        match target.rsplit_once(':') {
            // Двоеточий больше одного — голый IPv6 без порта.
            Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => host,
            _ => target,
        }
    }

    /// Что решено, как действие формы.
    pub fn action(&self) -> Action {
        match self.decision.as_str() {
            "direct" => Action::Direct,
            "block" => Action::Block,
            _ => Action::Tunnel,
        }
    }

    /// Решение словами: действие, сервер тоннеля и сработавшее правило.
    pub fn verdict(&self) -> String {
        let mut verdict = self.action().label().to_owned();
        let profile = self
            .decision
            .strip_prefix("proxy[")
            .and_then(|rest| rest.strip_suffix(']'));
        for detail in [profile, self.rule.as_deref()].into_iter().flatten() {
            verdict.push_str(" · ");
            verdict.push_str(detail);
        }
        verdict
    }

    /// Строка журнала столбцами: приложение, адрес, решение. Консоль моноширинная,
    /// поэтому столбцы держатся пробелами; длинное значение сдвигает только свою строку.
    pub fn line(&self) -> String {
        let who = self.process.as_deref().unwrap_or("?");
        format!(
            "{who:<APP_COLUMN$}  {:<TARGET_COLUMN$}  {}",
            self.target,
            self.verdict()
        )
    }
}

/// Ширина столбца приложения в знаках.
const APP_COLUMN: usize = 16;

/// Ширина столбца адреса в знаках.
const TARGET_COLUMN: usize = 36;

/// Варианты ширины адреса: от полного имени до двух последних меток. У адреса
/// и подсети вариант один.
pub fn widths(host: &str) -> Vec<String> {
    let labels: Vec<&str> = host.split('.').collect();
    if addresses::classify(host) != Some(Kind::Domain) || labels.len() <= 2 {
        return vec![host.to_owned()];
    }
    (0..=labels.len() - 2)
        .map(|from| labels[from..].join("."))
        .collect()
}

/// Окно «Правило для соединения».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRule {
    /// Соединение.
    pub flow: Flow,
    /// Ловить адрес.
    pub catch_host: bool,
    /// Выбранная ширина адреса — номер в [`widths`].
    pub width: usize,
    /// Ловить приложение.
    pub catch_app: bool,
    /// Действие новой группы.
    pub action: Action,
    /// Куда вписать: номер группы в наборе; `None` — новая группа.
    pub target: Option<usize>,
}

impl FlowRule {
    /// Окно по соединению: ловится адрес, действие — обратное нынешнему (окно
    /// открывают, чтобы решение поменять).
    pub fn new(flow: Flow) -> Self {
        let action = match flow.action() {
            Action::Direct => Action::Tunnel,
            Action::Tunnel | Action::Block => Action::Direct,
        };
        Self {
            flow,
            catch_host: true,
            width: 0,
            catch_app: false,
            action,
            target: None,
        }
    }

    /// Выбранный адрес.
    pub fn host(&self) -> String {
        let mut widths = widths(self.flow.host());
        widths.swap_remove(self.width.min(widths.len() - 1))
    }

    /// Путь приложения, если он известен.
    pub fn app(&self) -> Option<&str> {
        self.flow.process_path.as_deref()
    }

    /// Есть ли что добавлять.
    pub fn is_empty(&self) -> bool {
        !self.catch_host && !(self.catch_app && self.app().is_some())
    }

    /// Группы, которые добавленное расширит: номер, имя и действие.
    pub fn groups<'a>(&self, rules: &'a [RuleConfig]) -> Vec<(usize, &'a str, Action)> {
        rules
            .iter()
            .enumerate()
            .filter_map(|(index, found)| {
                let draft = rule::load(index, found)?;
                self.widens(&draft)
                    .then_some((index, found.name.as_str(), draft.action))
            })
            .collect()
    }

    /// Черновик группы с добавленным: новой или существующей с этим номером.
    pub fn draft(&self, rules: &[RuleConfig]) -> Option<Draft> {
        if self.is_empty() {
            return None;
        }
        let mut draft = match self.target {
            Some(index) => {
                rule::load(index, rules.get(index)?).filter(|draft| self.widens(draft))?
            }
            None => Draft {
                name: self.name(),
                action: self.action,
                ..Draft::default()
            },
        };

        if self.catch_host {
            draft.add(&self.host());
        }
        if self.catch_app
            && let Some(path) = self.app()
        {
            draft.toggle_process(path, true);
        }
        Some(draft)
    }

    /// Имя новой группы: приложение, если ловится оно, иначе адрес.
    fn name(&self) -> String {
        match (&self.flow.process, self.catch_app && self.app().is_some()) {
            (Some(process), true) => process.clone(),
            _ => self.host(),
        }
    }

    /// Расширит ли добавленное группу: каждый добавляемый раздел в ней уже есть.
    fn widens(&self, draft: &Draft) -> bool {
        let app = self.catch_app && self.app().is_some();
        !self.is_empty()
            && (!self.catch_host || !draft.hosts.is_empty())
            && (!app || !draft.processes.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn flow(target: &str, decision: &str) -> Flow {
        Flow {
            target: target.to_owned(),
            process: Some("synergy-core".to_owned()),
            process_path: Some("/Applications/Synergy.app/Contents/MacOS/synergy-core".to_owned()),
            decision: decision.to_owned(),
            rule: None,
        }
    }

    fn rules() -> Vec<RuleConfig> {
        serde_json::from_value(json!([
            { "id": "r1", "name": "LAN", "when": { "dest_ip": ["10.0.0.0/8"] }, "action": "direct" },
            { "id": "r2", "name": "Steam",
              "when": { "process_path": ["c:/steam/steam.exe"] }, "action": "tunnel" },
            { "id": "r3", "name": "Руками", "when": { "geo_ip": ["RU"] }, "action": "block" }
        ]))
        .expect("правила разбираются")
    }

    #[test]
    fn the_host_loses_its_port() {
        assert_eq!(
            flow("192.168.0.131:24800", "direct").host(),
            "192.168.0.131"
        );
        assert_eq!(flow("dns.google:853", "direct").host(), "dns.google");
        assert_eq!(flow("[2001:db8::1]:443", "direct").host(), "2001:db8::1");
        assert_eq!(flow("2001:db8::1", "direct").host(), "2001:db8::1");
    }

    #[test]
    fn a_line_keeps_its_columns() {
        let short = flow("dns.google:853", "proxy[hysteria]").line();
        let long = flow("192.168.0.131:24800", "direct").line();
        let column = |line: &str, value: &str| line.find(value).expect("значение в строке");

        assert_eq!(column(&short, "dns.google"), column(&long, "192.168.0.131"));
        assert_eq!(
            column(&short, crate::i18n::s().action_tunnel),
            column(&long, crate::i18n::s().action_direct)
        );
        assert!(short.ends_with(" · hysteria"), "{short}");
    }

    #[test]
    fn the_verdict_names_the_rule() {
        let mut flow = flow("a.example:443", "block");
        flow.rule = Some("ads".to_owned());
        assert_eq!(
            flow.verdict(),
            format!("{} · ads", crate::i18n::s().action_block)
        );
    }

    #[test]
    fn a_domain_can_be_widened_down_to_two_labels() {
        assert_eq!(
            widths("www.tm.trafficmanager.net"),
            [
                "www.tm.trafficmanager.net",
                "tm.trafficmanager.net",
                "trafficmanager.net"
            ]
        );
        assert_eq!(widths("dns.google"), ["dns.google"]);
        assert_eq!(widths("localhost"), ["localhost"]);
        assert_eq!(widths("10.0.0.1"), ["10.0.0.1"]);
    }

    #[test]
    fn the_window_offers_to_change_the_decision() {
        assert_eq!(
            FlowRule::new(flow("a.example:443", "proxy[hysteria]")).action,
            Action::Direct
        );
        assert_eq!(
            FlowRule::new(flow("a.example:443", "direct")).action,
            Action::Tunnel
        );
    }

    #[test]
    fn only_groups_that_grow_are_offered() {
        let mut window = FlowRule::new(flow("192.168.0.131:24800", "proxy[h]"));
        let names = |window: &FlowRule| -> Vec<String> {
            window
                .groups(&rules())
                .iter()
                .map(|(_, name, _)| name.to_string())
                .collect()
        };
        // Адрес — только туда, где адреса уже есть; правило руками форма не откроет.
        assert_eq!(names(&window), ["LAN"]);

        window.catch_host = false;
        window.catch_app = true;
        assert_eq!(names(&window), ["Steam"]);

        window.catch_host = true;
        assert!(names(&window).is_empty());
    }

    #[test]
    fn a_new_group_is_named_and_filled() {
        let mut window = FlowRule::new(flow("www.tm.trafficmanager.net:443", "proxy[h]"));
        window.width = 2;
        let draft = window.draft(&rules()).expect("есть что добавлять");
        assert_eq!(draft.name, "trafficmanager.net");
        assert_eq!(draft.hosts, ["trafficmanager.net"]);
        assert_eq!(draft.action, Action::Direct);
        assert!(draft.processes.is_empty());

        window.catch_app = true;
        assert_eq!(window.draft(&rules()).expect("группа").name, "synergy-core");
    }

    #[test]
    fn an_existing_group_is_extended_once() {
        let mut window = FlowRule::new(flow("192.168.0.131:24800", "proxy[h]"));
        window.target = Some(0);
        let draft = window.draft(&rules()).expect("группа");
        assert_eq!(draft.index, Some(0));
        assert_eq!(draft.hosts, ["10.0.0.0/8", "192.168.0.131"]);
        assert_eq!(draft.action, Action::Direct);

        let mut again = rules();
        again[0] = draft.build("r1").expect("собирается");
        assert_eq!(window.draft(&again).expect("группа").hosts, draft.hosts);
    }

    #[test]
    fn nothing_to_catch_gives_nothing() {
        let mut window = FlowRule::new(flow("a.example:443", "direct"));
        window.catch_host = false;
        window.flow.process_path = None;
        window.catch_app = true;
        assert!(window.is_empty());
        assert!(window.draft(&rules()).is_none());
    }
}
