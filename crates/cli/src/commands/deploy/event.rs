//! Ход установки: строки `::…` из `install.sh` и их JSON для окна.

use serde::Serialize;

/// Одно событие установки.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "lowercase")]
pub enum Event {
    /// Начался шаг.
    Step {
        /// Имя шага: `docker`, `build`, `cert`, …
        id: String,
    },
    /// Шаг удался.
    Ok {
        /// Текст для человека.
        text: String,
    },
    /// Пояснение по ходу шага.
    Info {
        /// Текст для человека.
        text: String,
    },
    /// Ссылка-приглашение; последнее при успехе.
    Link {
        /// `pingwin://…`.
        link: String,
    },
    /// Установка остановилась; в JSON не печатается — становится ошибкой.
    Fail {
        /// Причина.
        text: String,
    },
}

/// Разбирает строку вывода сценария; прочие строки — шум.
pub fn parse_line(line: &str) -> Option<Event> {
    let rest = line.trim_end_matches(['\r', '\n']).strip_prefix("::")?;
    let (kind, value) = rest.split_once(' ').unwrap_or((rest, ""));
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let value = value.to_owned();
    match kind {
        "step" => Some(Event::Step { id: value }),
        "ok" => Some(Event::Ok { text: value }),
        "info" => Some(Event::Info { text: value }),
        "link" if value.starts_with("pingwin://") => Some(Event::Link { link: value }),
        "fail" => Some(Event::Fail { text: value }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_lines_are_parsed() {
        assert_eq!(
            parse_line("::step docker\n"),
            Some(Event::Step {
                id: "docker".into()
            })
        );
        assert_eq!(
            parse_line("::ok уже стоит: Docker version 27.3.1, build ce12230"),
            Some(Event::Ok {
                text: "уже стоит: Docker version 27.3.1, build ce12230".into()
            })
        );
        assert_eq!(
            parse_line("::info ставлю — это пара минут\r"),
            Some(Event::Info {
                text: "ставлю — это пара минут".into()
            })
        );
        assert_eq!(
            parse_line("::link pingwin://client:pw@vpn.example.com:443?name=x"),
            Some(Event::Link {
                link: "pingwin://client:pw@vpn.example.com:443?name=x".into()
            })
        );
        assert_eq!(
            parse_line("::fail нужны права root"),
            Some(Event::Fail {
                text: "нужны права root".into()
            })
        );
    }

    #[test]
    fn noise_is_ignored() {
        for line in [
            "",
            "Step 3/12 : RUN cargo build",
            "::",
            "::step",
            "::step ",
            "::bogus x",
            "::link https://evil.example",
            " ::ok indented",
        ] {
            assert_eq!(parse_line(line), None, "{line:?}");
        }
    }

    #[test]
    fn json_matches_what_the_window_reads() {
        let json = |event: Event| serde_json::to_string(&event).expect("JSON");
        assert_eq!(
            json(Event::Step { id: "cert".into() }),
            r#"{"event":"step","id":"cert"}"#
        );
        assert_eq!(
            json(Event::Ok { text: "т".into() }),
            r#"{"event":"ok","text":"т"}"#
        );
        assert_eq!(
            json(Event::Link {
                link: "pingwin://x".into()
            }),
            r#"{"event":"link","link":"pingwin://x"}"#
        );
    }
}
