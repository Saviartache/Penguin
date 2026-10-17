//! Окно в покое: консоль и одна кнопка.
//!
//! Консоль рисует [`crate::console`]; здесь её строки: конфигурация, состояние,
//! заголовок трафика, поток данных (пока соединение поднимается или работает) и
//! цифры, прижатые к нижнему краю.

use iced::Element;
use iced::widget::text;
use penguin_core::state::TunnelState;
use uikit::layout::{Flex, Sizable, Size, gap, px};
use uikit::tokens::type_scale;
use uikit::widgets::Button;

use crate::app::message::{HomeMessage, Message};
use crate::app::state::{State, UpdateStatus};
use crate::console::{self, Line, Reveal};
use crate::screens::tunnel::{Tone, describe, describe_button, describe_service_button};

/// Высота кнопки: единственное действие окна не должно быть легко промахнуть.
const BUTTON_HEIGHT: f32 = 40.0;

/// Значение, которого нет: дефис, а не тире (см. правило про глифы в [`crate::console`]).
const NONE: &str = "-";

/// Ход потока у поднятого, но молчащего тоннеля.
const IDLE_FLOW: f32 = 0.2;

/// Собирает компактный экран.
pub fn view(state: &State) -> Element<'_, Message> {
    // Размер колонки явный: растянутая консоль в группе «по содержимому» схлопнется.
    Flex::col()
        .w(Size::FILL)
        .h(Size::FILL)
        .push(console::console(
            &state.palette,
            &lines(state),
            reveal(state),
        ))
        .push_auto(button(state))
        .gap(gap::SM)
        .build()
}

fn lines(state: &State) -> Vec<Line> {
    let mut lines = config(state);
    lines.push(status(state));
    lines.extend(update_notice(state));
    let traffic_head = Line::Section(crate::i18n::s().traffic.to_uppercase());
    if streaming(state) {
        lines.push(traffic_head);
        lines.push(Line::Stream(load(state)));
    } else {
        // Пустота прижимает раздел трафика к нижнему краю.
        lines.push(Line::Space);
        lines.push(traffic_head);
    }
    lines.extend(traffic(state));
    lines
}

/// Одна строка, когда есть новый выпуск; иначе ничего.
fn update_notice(state: &State) -> Option<Line> {
    let UpdateStatus::Available(found) = &state.updates.status else {
        return None;
    };
    let strings = crate::i18n::s();
    Some(pair(
        strings.update_label,
        format!("{} ({})", found.version, strings.update_in_settings),
    ))
}

/// Поток показывается, пока тоннель поднимается, работает или переподключается.
fn streaming(state: &State) -> bool {
    matches!(
        state.connection.tunnel,
        TunnelState::Connecting { .. }
            | TunnelState::Connected { .. }
            | TunnelState::Reconnecting { .. }
    )
}

/// Загрузка потока: свежая скорость долей от пика окна истории.
///
/// Ноль берётся из состояния, а не из отсчёта: после падения тоннеля в истории
/// остаётся последняя ненулевая скорость. У поднятого тоннеля пол [`IDLE_FLOW`].
fn load(state: &State) -> f32 {
    let connection = &state.connection;
    if !matches!(connection.tunnel, TunnelState::Connected { .. }) {
        return 0.0;
    }

    let scale = connection.graph_scale() as f32;
    let rate = connection
        .graph
        .back()
        .map_or(0.0, |point| point.up_bps.max(point.down_bps) as f32 / scale);

    IDLE_FLOW + (1.0 - IDLE_FLOW) * rate
}

fn reveal(state: &State) -> Reveal {
    match state.boot.progress() {
        Some(fraction) if fraction < 1.0 => Reveal::Typing(fraction),
        _ => Reveal::Done,
    }
}

fn config(state: &State) -> Vec<Line> {
    let strings = crate::i18n::s();
    let head = Line::Section(strings.configuration.to_uppercase());

    let Some(profile) = state.config.active() else {
        return vec![head, pair(strings.profile, strings.no_profiles.to_owned())];
    };

    let latency = state
        .servers
        .latencies
        .iter()
        .find(|(id, _)| id == profile.id.as_str())
        .and_then(|(_, rtt)| *rtt)
        .map_or_else(
            || NONE.to_owned(),
            |rtt| format!("{rtt} {}", strings.millis),
        );

    vec![
        head,
        pair(strings.profile, profile.name.clone()),
        pair(
            strings.server,
            crate::screens::servers::server_of(profile)
                .map_or_else(|| NONE.to_owned(), str::to_owned),
        ),
        pair(strings.protocol, profile.outbound.protocol.clone()),
        pair(strings.latency, latency),
        pair(
            strings.mode,
            crate::i18n::mode_label(state.config.routing.mode).to_owned(),
        ),
        pair(strings.rules, state.config.routing.rules.len().to_string()),
    ]
}

/// Цифры под потоком; заголовком им служит сам поток.
fn traffic(state: &State) -> Vec<Line> {
    let strings = crate::i18n::s();
    let connection = &state.connection;

    vec![
        pair(strings.downloaded, rate(connection.rate.down_bps)),
        pair(strings.uploaded, rate(connection.rate.up_bps)),
        pair(strings.connections, connection.connections.to_string()),
    ]
}

/// Состояние тоннеля — словом и цветом.
fn status(state: &State) -> Line {
    let connection = &state.connection;

    // Остановка первой: «Подключено» закрывающемуся окну — вранье.
    let (label, tone) = if connection.stopping {
        (crate::i18n::s().daemon_stopping.to_owned(), Tone::Busy)
    } else if connection.online {
        describe(&connection.tunnel_now())
    } else if connection.starting {
        (crate::i18n::s().service_starting.to_owned(), Tone::Busy)
    } else {
        (crate::i18n::s().daemon_offline.to_owned(), Tone::Trouble)
    };

    Line::Toned(
        crate::i18n::s().status.to_uppercase(),
        label.to_uppercase(),
        tone.color(&state.palette),
    )
}

/// Строка «поле — значение»; заглавные только для консоли, переводы общие.
fn pair(label: &str, value: String) -> Line {
    Line::Pair(label.to_uppercase(), value)
}

fn button(state: &State) -> Element<'_, Message> {
    let connection = &state.connection;
    let (label, variant) = if connection.online {
        describe_button(&connection.tunnel)
    } else {
        describe_service_button(connection.starting)
    };

    Button::new(text(label).size(type_scale::LEAD))
        .variant(variant)
        .h(px(BUTTON_HEIGHT))
        .w(Size::FILL)
        .on_press(Message::Home(HomeMessage::ToggleConnection))
        .into()
}

fn rate(bits: u64) -> String {
    format!("{}/с", size(bits / 8))
}

fn size(bytes: u64) -> String {
    const STEP: f64 = 1024.0;
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];

    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= STEP && unit + 1 < UNITS.len() {
        value /= STEP;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use iced::Length;
    use penguin_config::schema::outbound::RawOutbound;
    use penguin_config::schema::profile::Profile;
    use penguin_core::id::ProfileId;
    use penguin_core::state::TunnelState;
    use serde_json::json;

    use super::*;

    /// Знаки, которых в моноширинном шрифте кита может не быть.
    const RISKY: [char; 3] = ['—', '–', '…'];

    fn with_profile() -> State {
        let mut state = State::default();
        state.config.profiles.push(Profile::new(
            "home",
            "home",
            RawOutbound::new("hysteria2", json!({ "server": "example.com:443" })),
        ));
        state
    }

    #[test]
    fn the_column_declares_its_own_size() {
        let state = State::default();
        let element = view(&state);
        let size = element.as_widget().size();

        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn renders_without_profiles() {
        let state = State::default();
        let _ = view(&state);
    }

    #[test]
    fn renders_connected() {
        let mut state = State::default();
        state.connection.online = true;
        state.connection.set_tunnel(TunnelState::Connected {
            profile: ProfileId::new("home"),
            uptime_secs: 42,
        });
        let _ = view(&state);
    }

    #[test]
    fn the_console_opens_with_the_configuration() {
        let state = with_profile();
        let Some(Line::Section(head)) = lines(&state).into_iter().next() else {
            panic!("первой строкой не заголовок раздела")
        };
        assert_eq!(head, crate::i18n::s().configuration.to_uppercase());
    }

    #[test]
    fn without_a_connection_there_is_no_stream() {
        for state in [State::default(), with_profile()] {
            let lines = lines(&state);
            assert!(!lines.iter().any(|line| matches!(line, Line::Stream(_))));
            assert!(matches!(lines.last(), Some(Line::Pair(..))), "цифр нет");

            let at = lines
                .iter()
                .position(|line| matches!(line, Line::Space))
                .expect("пустоты нет");
            assert!(matches!(lines[at + 1], Line::Section(_)), "не над трафиком");
        }
    }

    #[test]
    fn the_stream_appears_once_the_connection_starts() {
        let mut state = with_profile();
        for tunnel in [
            TunnelState::Connecting {
                profile: ProfileId::new("home"),
            },
            TunnelState::Connected {
                profile: ProfileId::new("home"),
                uptime_secs: 1,
            },
        ] {
            state.connection.set_tunnel(tunnel);
            assert!(
                lines(&state)
                    .iter()
                    .any(|line| matches!(line, Line::Stream(_)))
            );
        }
    }

    #[test]
    fn a_stream_without_a_tunnel_stays_at_rest() {
        let mut state = State::default();
        state.connection.apply_throughput(
            penguin_core::stats::Throughput {
                up_bps: 5_000,
                down_bps: 0,
            },
            penguin_core::stats::Traffic::default(),
            0,
        );

        assert_eq!(load(&state), 0.0, "тоннеля нет — полотно стоит");

        state.connection.online = true;
        state.connection.set_tunnel(TunnelState::Connected {
            profile: ProfileId::new("home"),
            uptime_secs: 1,
        });
        assert_eq!(load(&state), 1.0, "тоннель поднят — идёт обмен");
    }

    #[test]
    fn a_silent_tunnel_still_keeps_the_stream_going() {
        let mut state = State::default();
        state.connection.online = true;
        state.connection.set_tunnel(TunnelState::Connected {
            profile: ProfileId::new("home"),
            uptime_secs: 1,
        });

        assert_eq!(load(&state), IDLE_FLOW, "молчащий тоннель остановил поток");
    }

    #[test]
    fn the_stream_reads_the_freshest_sample_against_the_peak() {
        let mut state = State::default();
        state.connection.online = true;
        state.connection.set_tunnel(TunnelState::Connected {
            profile: ProfileId::new("home"),
            uptime_secs: 1,
        });
        assert_eq!(load(&state), IDLE_FLOW, "истории нет — обмена нет");

        for step in 1..=4 {
            state.connection.apply_throughput(
                penguin_core::stats::Throughput {
                    up_bps: step * 1_000,
                    down_bps: 0,
                },
                penguin_core::stats::Traffic::default(),
                0,
            );
        }
        assert_eq!(load(&state), 1.0, "свежий отсчёт он же и пик");

        state.connection.apply_throughput(
            penguin_core::stats::Throughput {
                up_bps: 1_000,
                down_bps: 0,
            },
            penguin_core::stats::Traffic::default(),
            0,
        );
        assert_eq!(
            load(&state),
            IDLE_FLOW + (1.0 - IDLE_FLOW) * 0.25,
            "скорость упала вчетверо от пика"
        );
    }

    #[test]
    fn the_stream_stands_between_the_status_and_its_numbers() {
        let mut state = with_profile();
        state.connection.set_tunnel(TunnelState::Connected {
            profile: ProfileId::new("home"),
            uptime_secs: 1,
        });
        let lines = lines(&state);

        let at = lines
            .iter()
            .position(|line| matches!(line, Line::Stream(_)))
            .expect("потока нет");
        assert!(matches!(lines[at - 1], Line::Section(_)), "без подписи");
        assert!(matches!(lines[at + 1], Line::Pair(..)), "не перед цифрами");
    }

    #[test]
    fn the_status_line_says_what_is_happening() {
        let mut state = State::default();
        state.connection.mark_offline("служба остановлена");

        let Line::Toned(label, value, _) = status(&state) else {
            panic!("состояние не строкой состояния")
        };
        assert_eq!(label, crate::i18n::s().status.to_uppercase());
        assert_eq!(value, crate::i18n::s().daemon_offline.to_uppercase());
    }

    #[test]
    fn a_service_we_are_stopping_ourselves_is_not_called_missing() {
        let mut state = State::default();
        state.connection.stopping = true;
        state.connection.mark_offline("служба остановлена");

        let Line::Toned(_, value, _) = status(&state) else {
            panic!("состояние не строкой состояния")
        };
        assert_eq!(value, crate::i18n::s().daemon_stopping.to_uppercase());
    }

    #[test]
    fn labels_read_as_console_labels() {
        let Line::Pair(label, _) = pair(crate::i18n::s().mode, "TUN".to_owned()) else {
            panic!("не строка поля")
        };
        assert_eq!(label, crate::i18n::s().mode.to_uppercase());
    }

    #[test]
    fn no_console_value_uses_a_glyph_the_font_may_lack() {
        for line in &lines(&with_profile()) {
            let (label, value) = match line {
                Line::Pair(label, value) | Line::Toned(label, value, _) => {
                    (label.as_str(), value.as_str())
                }
                Line::Section(label) => (label.as_str(), ""),
                Line::Stream(_) | Line::Space => continue,
            };

            for glyph in RISKY {
                assert!(
                    !label.contains(glyph),
                    "в подписи «{label}» знак {glyph}, которого в шрифте может не быть"
                );
                assert!(
                    !value.contains(glyph),
                    "в значении «{value}» знак {glyph}, которого в шрифте может не быть"
                );
            }
        }
    }

    #[test]
    fn a_profile_without_a_latency_still_ends_at_the_right_edge() {
        let latency = lines(&with_profile())
            .into_iter()
            .find_map(|line| match line {
                Line::Pair(label, value) if label == crate::i18n::s().latency.to_uppercase() => {
                    Some(value)
                }
                _ => None,
            })
            .expect("строки задержки нет");

        assert_eq!(latency, NONE);
    }

    #[test]
    fn sizes_read_in_human_units() {
        assert_eq!(size(0), "0 Б");
        assert_eq!(size(512), "512 Б");
        assert_eq!(size(1024), "1.0 КБ");
        assert_eq!(size(1024 * 1024 * 3 / 2), "1.5 МБ");
    }

    #[test]
    fn rate_is_bytes_per_second_not_bits() {
        assert_eq!(rate(8 * 1024), "1.0 КБ/с");
    }
}
