//! Ход развёртывания: строки `stdout` CLI и этапы, как их показывает окно.
//!
//! Строка — объект JSON: `{"event":"step","id":"docker"}`,
//! `{"event":"ok"|"info","text":"…"}`, `{"event":"link","link":"pingwin://…"}`.

use serde_json::Value;

use crate::i18n::Strings;

type Label = fn(&Strings) -> &'static str;

/// Этапы в порядке CLI: идентификатор и подпись.
const STAGES: [(&str, Label); 11] = [
    ("inspect", |s| s.stage_inspect),
    ("docker", |s| s.stage_docker),
    ("memory", |s| s.stage_memory),
    ("source", |s| s.stage_source),
    ("build", |s| s.stage_build),
    ("cert", |s| s.stage_cert),
    ("keys", |s| s.stage_keys),
    ("start", |s| s.stage_start),
    ("firewall", |s| s.stage_firewall),
    ("check", |s| s.stage_check),
    ("link", |s| s.stage_link),
];

/// Строка вывода CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Начался этап.
    Step(String),
    /// Новость текущего этапа (`ok` или `info`).
    Text(String),
    /// Готовая ссылка-приглашение.
    Link(String),
}

/// Разбирает строку `stdout`; чужое (не JSON, неизвестное событие) — `None`.
pub fn parse_line(line: &str) -> Option<Event> {
    let value: Value = serde_json::from_str(line.trim()).ok()?;
    let field = |key: &str| value.get(key)?.as_str().map(str::to_owned);
    match value.get("event")?.as_str()? {
        "step" => field("id").map(Event::Step),
        "ok" | "info" => field("text").map(Event::Text),
        "link" => field("link").map(Event::Link),
        _ => None,
    }
}

/// Подпись этапа; неизвестный показывается своим идентификатором.
pub fn title(id: &str) -> &str {
    STAGES
        .iter()
        .find(|(known, _)| *known == id)
        .map_or(id, |(_, label)| label(crate::i18n::s()))
}

/// Место этапа относительно текущего.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// Пройден.
    Done,
    /// Идёт.
    Current,
    /// Впереди.
    Pending,
}

/// Что известно о ходе развёртывания.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Progress {
    /// Пришедшие этапы, которых нет в [`STAGES`].
    unknown: Vec<String>,
    current: Option<String>,
    /// Последняя новость текущего этапа.
    pub text: String,
    /// Присланная ссылка.
    pub link: Option<String>,
}

impl Progress {
    /// Принимает строку вывода.
    pub fn apply(&mut self, event: Event) {
        match event {
            Event::Step(id) => {
                let known = STAGES.iter().any(|(known, _)| *known == id);
                if !known && !self.unknown.contains(&id) {
                    self.unknown.push(id.clone());
                }
                self.current = Some(id);
                self.text.clear();
            }
            Event::Text(text) => self.text = text,
            Event::Link(link) => self.link = Some(link),
        }
    }

    /// Идущий этап.
    pub fn current(&self) -> Option<&str> {
        self.current.as_deref()
    }

    /// Этапы по порядку: известные, потом пришедшие неизвестные. Всё до
    /// текущего пройдено: пропущенный CLI этап не нужен.
    pub fn stages(&self) -> Vec<(&str, Mark)> {
        let ids: Vec<&str> = STAGES
            .iter()
            .map(|(id, _)| *id)
            .chain(self.unknown.iter().map(String::as_str))
            .collect();
        let at = self
            .current()
            .and_then(|current| ids.iter().position(|id| *id == current));
        ids.into_iter()
            .enumerate()
            .map(|(index, id)| {
                let mark = match at {
                    Some(at) if index < at => Mark::Done,
                    Some(at) if index == at => Mark::Current,
                    _ => Mark::Pending,
                };
                (id, mark)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_of_the_contract_are_parsed() {
        assert_eq!(
            parse_line(r#"{"event":"step","id":"docker"}"#),
            Some(Event::Step("docker".to_owned()))
        );
        assert_eq!(
            parse_line(r#"{"event":"ok","text":"стоит 27.1"}"#),
            Some(Event::Text("стоит 27.1".to_owned()))
        );
        assert_eq!(
            parse_line(r#" {"event":"info","text":"жду"} "#),
            Some(Event::Text("жду".to_owned()))
        );
        assert_eq!(
            parse_line(r#"{"event":"link","link":"pingwin://p@h:443?key=k"}"#),
            Some(Event::Link("pingwin://p@h:443?key=k".to_owned()))
        );
    }

    #[test]
    fn foreign_lines_are_skipped() {
        assert_eq!(parse_line(""), None);
        assert_eq!(parse_line("Step 3/9 : RUN cargo build"), None);
        assert_eq!(parse_line(r#"{"event":"новое"}"#), None);
        assert_eq!(parse_line(r#"{"event":"step"}"#), None);
    }

    #[test]
    fn known_stages_have_titles_and_unknown_keep_their_id() {
        assert_eq!(title("docker"), crate::i18n::s().stage_docker);
        assert_eq!(title("swap2"), "swap2");
    }

    #[test]
    fn stages_before_the_current_one_are_done() {
        let mut progress = Progress::default();
        assert!(progress.stages().iter().all(|(_, m)| *m == Mark::Pending));

        progress.apply(Event::Step("inspect".to_owned()));
        progress.apply(Event::Text("Ubuntu 24.04".to_owned()));
        progress.apply(Event::Step("memory".to_owned()));
        assert!(progress.text.is_empty(), "новость прошлого этапа осталась");

        let stages = progress.stages();
        assert_eq!(stages[0], ("inspect", Mark::Done));
        assert_eq!(stages[1], ("docker", Mark::Done));
        assert_eq!(stages[2], ("memory", Mark::Current));
        assert_eq!(stages[3], ("source", Mark::Pending));
    }

    #[test]
    fn an_unknown_stage_is_listed_once_after_the_known() {
        let mut progress = Progress::default();
        progress.apply(Event::Step("swap2".to_owned()));
        progress.apply(Event::Step("swap2".to_owned()));
        let stages = progress.stages();
        assert_eq!(stages.len(), STAGES.len() + 1);
        assert_eq!(stages.last(), Some(&("swap2", Mark::Current)));
        assert_eq!(stages[0].1, Mark::Done);
    }
}
