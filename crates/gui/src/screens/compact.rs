//! Окно в покое: консоль и одна кнопка.
//!
//! Ради этого клиент и открывают: посмотреть, куда он ведёт, и нажать. Всё
//! остальное — серверы, правила, журнал, настройки — живёт за кнопкой настроек
//! в шапке и появляется, только когда за ним пришли.
//!
//! Экран — консольный вывод во всю площадь, а не карточка в середине пустоты.
//! Рисует его [`crate::console`]; здесь только то, из каких строк он состоит:
//!
//! - сверху конфигурация: куда тоннель поведёт. Первой строкой, без шапки с
//!   именем программы — имя стоит в заголовке окна, и второй раз его читать
//!   незачем;
//! - под ней состояние — словом и цветом;
//! - дальше график: он забирает всю высоту, не занятую текстом. Раньше на этом
//!   месте была пустота — та самая, из-за которой окно выглядело недозаполненным;
//! - над графиком его подпись, под ним его цифры: скорость приёма и отдачи,
//!   число соединений;
//! - последней строкой приглашение с мигающим курсором.
//!
//! Конфигурация и трафик показываются вместе, а не по очереди: переключение
//! содержимого на одном месте заставляло бы искать глазами, что там сейчас.

use iced::Element;
use iced::widget::text;
use uikit::layout::{Flex, Sizable, Size, gap, px};
use uikit::style::tokens::type_scale;
use uikit::widgets::Button;

use crate::app::message::{HomeMessage, Message};
use crate::app::state::{GRAPH_POINTS, State};
use crate::console::{self, Line, Reveal};
use crate::screens::tunnel::{Tone, describe, describe_button};

/// Высота кнопки.
///
/// Заметно выше обычной: это единственное действие окна в покое, и промахнуться
/// по нему не должно быть возможности.
const BUTTON_HEIGHT: f32 = 40.0;

/// Значение, которого нет.
///
/// Дефис, а не длинное тире: тире в моноширинном шрифте кита нет, подставленный
/// вместо него системный глиф шире знака, и значение уезжало за правый край —
/// единственная строка, где ровный край консоли ломался (см.
/// [`crate::console`], правило про глифы).
const NONE: &str = "-";

/// Приглашение у нижнего края.
///
/// Латиницей и с обратной косой — приглашение `COMMAND.COM`, а не приглашение
/// оболочки Unix: окно и живёт на Windows.
const PROMPT: &str = "C:\\OSTRIACKI>";

/// Собирает компактный экран.
pub fn view(state: &State) -> Element<'_, Message> {
    // Колонка объявляет размер сама. Без этого она «по содержимому», а
    // растянутая консоль внутри такой группы схлопывается в ноль: на экране
    // осталась бы одна кнопка, прижатая к верхнему краю.
    Flex::col()
        .w(Size::FILL)
        .h(Size::FILL)
        .push(screen(state))
        .push_auto(button(state))
        .gap(gap::SM)
        .build()
}

/// Консоль целиком.
fn screen(state: &State) -> Element<'_, Message> {
    let mut lines = config(state);

    lines.push(status(state));
    // Заголовок раздела стоит над графиком и служит ему подписью: цифры под ним
    // и так читаются как его же. График забирает всю высоту, которую не занял
    // текст, — он же и прижимает цифры с приглашением к нижнему краю.
    lines.push(Line::Section(crate::i18n::s().traffic.to_uppercase()));
    lines.push(Line::Graph(history(state)));
    lines.extend(traffic(state));
    lines.push(Line::Prompt(PROMPT.to_owned()));

    console::console(&state.palette, &lines, reveal(state))
}

/// История скорости долями от наибольшей — столбик на отсчёт.
///
/// Дополняется нулями слева до полной длины истории: без этого первые полминуты
/// после подключения график рос бы вправо, растягивая каждый столбик на треть
/// окна, а его высота ничего не значила бы — она считается от наибольшего
/// отсчёта, а не от края.
fn history(state: &State) -> Vec<f32> {
    let connection = &state.connection;
    let scale = connection.graph_scale() as f32;

    let mut points = vec![0.0; GRAPH_POINTS.saturating_sub(connection.graph.len())];
    points.extend(
        connection
            .graph
            .iter()
            .map(|point| point.up_bps.max(point.down_bps) as f32 / scale),
    );
    points
}

/// Что печатается при первом открытии, а дальше показывается целиком.
fn reveal(state: &State) -> Reveal {
    match state.boot.progress() {
        Some(fraction) if fraction < 1.0 => Reveal::Typing(fraction),
        _ => Reveal::Done {
            cursor: state.boot.cursor(),
        },
    }
}

/// Куда тоннель поведёт.
fn config(state: &State) -> Vec<Line> {
    let strings = crate::i18n::s();
    let head = Line::Section(strings.configuration.to_uppercase());

    let Some(profile) = state.config.active() else {
        // Профилей нет — говорить о конфигурации нечего, и столбец прочерков
        // читался бы как поломка.
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
            crate::i18n::mode_label(state.config.routing.mode.as_str()).to_owned(),
        ),
        pair(strings.rules, state.config.routing.rules.len().to_string()),
    ]
}

/// Цифры под графиком.
///
/// Заголовка раздела здесь нет: график над ними — и есть заголовок, а строка с
/// чертой отняла бы у него высоту ни за что.
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

    let (label, tone) = if connection.online {
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

/// Строка «поле — значение» заглавными.
///
/// Регистр приводится здесь, а не в переводах: подписи те же, что и на других
/// экранах, а заглавные — это про консоль. Держать ради неё второй набор
/// переводов значило бы однажды поправить один и забыть другой.
fn pair(label: &str, value: String) -> Line {
    Line::Pair(label.to_uppercase(), value)
}

/// Единственное действие окна.
fn button(state: &State) -> Element<'_, Message> {
    let (label, variant) = describe_button(&state.connection.tunnel);

    Button::new(text(label).size(type_scale::LEAD))
        .variant(variant)
        .h(px(BUTTON_HEIGHT))
        .w(Size::FILL)
        .on_press(Message::Home(HomeMessage::ToggleConnection))
        .into()
}

/// Скорость человеческими единицами.
fn rate(bits: u64) -> String {
    format!("{}/с", size(bits / 8))
}

/// Объём человеческими единицами.
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
    ///
    /// Подставленный вместо такого знака системный глиф шире знака, и значение
    /// уезжает за правый край — см. правило про глифы в [`crate::console`].
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
        // Растянутая консоль внутри группы «по содержимому» схлопывается в
        // ноль, и на экране остаётся одна кнопка, прижатая к верхнему краю.
        // Проверено на живом окне — выглядит как пустой экран.
        let state = State::default();
        let element = view(&state);
        let size = element.as_widget().size();

        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn renders_without_profiles() {
        // Первый запуск: сервера ещё нет, а окно уже открыто.
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
        // Шапки с именем программы нет намеренно: имя стоит в заголовке окна.
        let state = State::default();
        let Some(Line::Section(head)) = config(&state).into_iter().next() else {
            panic!("первой строкой не заголовок раздела")
        };
        assert_eq!(head, crate::i18n::s().configuration.to_uppercase());
    }

    #[test]
    fn the_graph_gets_a_column_per_sample_of_history() {
        // Столбиков всегда столько, сколько отсчётов держит окно: иначе первые
        // полминуты после подключения каждый растягивался бы на треть окна.
        let state = State::default();
        assert_eq!(history(&state).len(), GRAPH_POINTS);

        let mut state = state;
        for step in 0..GRAPH_POINTS as u64 * 2 {
            state.connection.apply_throughput(
                penguin_core::stats::Throughput {
                    up_bps: step,
                    down_bps: step,
                },
                penguin_core::stats::Traffic::default(),
                0,
            );
        }
        assert_eq!(history(&state).len(), GRAPH_POINTS);
    }

    #[test]
    fn the_graph_stands_between_the_status_and_its_numbers() {
        // График — единственная строка, которой достаётся высота; стоять она
        // должна там, где раньше была пустота, а не под цифрами.
        let state = State::default();
        let mut lines = config(&state);
        lines.push(status(&state));
        lines.push(Line::Section(crate::i18n::s().traffic.to_uppercase()));
        lines.push(Line::Graph(history(&state)));
        lines.extend(traffic(&state));

        let at = lines
            .iter()
            .position(|line| matches!(line, Line::Graph(_)))
            .expect("графика нет");
        assert!(matches!(lines[at - 1], Line::Section(_)), "без подписи");
        assert!(matches!(lines[at + 1], Line::Pair(..)), "не перед цифрами");
    }

    #[test]
    fn the_status_line_says_what_is_happening() {
        // Состояние стоит строкой консоли; потерять его значит оставить окно
        // без единственного ответа, за которым его открывают.
        let mut state = State::default();
        state.connection.mark_offline("служба остановлена");

        let Line::Toned(label, value, _) = status(&state) else {
            panic!("состояние не строкой состояния")
        };
        assert_eq!(label, crate::i18n::s().status.to_uppercase());
        assert_eq!(value, crate::i18n::s().daemon_offline.to_uppercase());
    }

    #[test]
    fn labels_read_as_console_labels() {
        // Разнобой регистра в столбце подписей — первое, что видно в консоли.
        let Line::Pair(label, _) = pair(crate::i18n::s().mode, "TUN".to_owned()) else {
            panic!("не строка поля")
        };
        assert_eq!(label, crate::i18n::s().mode.to_uppercase());
    }

    #[test]
    fn no_console_value_uses_a_glyph_the_font_may_lack() {
        // Ровно так уезжала за правый край строка задержки: прочерк длинным
        // тире брался из системного шрифта и рисовался шире, чем был измерен.
        // Проверяется списком, а не глазами: увидеть это можно только на живом
        // окне и только в той строке, где значение короткое.
        let state = with_profile();
        let mut lines = config(&state);
        lines.push(status(&state));
        lines.extend(traffic(&state));

        for line in &lines {
            let (label, value) = match line {
                Line::Pair(label, value) | Line::Toned(label, value, _) => {
                    (label.as_str(), value.as_str())
                }
                Line::Section(label) | Line::Prompt(label) => (label.as_str(), ""),
                // У графика знаков нет вовсе — он рисуется столбиками.
                Line::Graph(_) => continue,
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
        // Задержки нет — на её месте прочерк, и он обязан быть знаком шрифта.
        let state = with_profile();
        let latency = config(&state)
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
        // Счётчики приходят в битах, а человек считает байтами: восьмикратная
        // разница в подписи — это не мелочь.
        assert_eq!(rate(8 * 1024), "1.0 КБ/с");
    }
}
