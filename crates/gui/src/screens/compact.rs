//! Окно в покое: одна панель и одна кнопка.
//!
//! Ради этого клиент и открывают: посмотреть, куда он ведёт, и нажать. Всё
//! остальное — серверы, правила, журнал, настройки — живёт за кнопкой
//! настроек в шапке и появляется, только когда за ним пришли.
//!
//! Панель по состоянию меняет не место, а содержимое: пока тоннель опущен —
//! куда он поведёт, когда поднят — как идёт трафик. Двух панелей нет
//! намеренно: в окне размером с ладонь вторая означала бы половину площади,
//! занятую тем, что сейчас не нужно.

use iced::widget::text;
use iced::{Alignment, Element};
use penguin_core::state::TunnelState;
use uikit::layout::{Flex, Sizable, Size, gap, px};
use uikit::style::tokens::type_scale;
use uikit::widgets::Button;

use crate::app::message::{HomeMessage, Message};
use crate::app::state::State;
use crate::ascii::{self, Row};
use crate::screens::tunnel::{Tone, describe, describe_button, format_uptime};

/// Высота кнопки.
///
/// Заметно выше обычной: это единственное действие окна в покое, и промахнуться
/// по нему не должно быть возможности.
const BUTTON_HEIGHT: f32 = 40.0;

/// Собирает компактный экран.
pub fn view(state: &State) -> Element<'_, Message> {
    // Колонка объявляет размер сама. Без этого она «по содержимому», а
    // растянутая панель внутри такой группы схлопывается в ноль: на экране
    // остались бы строка состояния и кнопка, прижатые к верхнему краю.
    Flex::col()
        .w(Size::FILL)
        .h(Size::FILL)
        .push(panel(state))
        .push_auto(headline(state))
        .push_auto(button(state))
        .gap(gap::SM)
        .build()
}

/// Панель: конфигурация или трафик.
fn panel(state: &State) -> Element<'_, Message> {
    if state.connection.tunnel.is_active() {
        traffic(state)
    } else {
        config(state)
    }
}

/// Куда тоннель поведёт.
fn config(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    let Some(profile) = state.config.active() else {
        // Профилей нет — говорить о конфигурации нечего, и рамка с прочерками
        // читалась бы как поломка.
        return ascii::panel(
            strings.configuration,
            &[Row::Pair(strings.profile, strings.no_profiles.to_owned())],
        );
    };

    let latency = state
        .servers
        .latencies
        .iter()
        .find(|(id, _)| id == profile.id.as_str())
        .and_then(|(_, rtt)| *rtt)
        .map_or_else(|| "—".to_owned(), |rtt| format!("{rtt} {}", strings.millis));

    ascii::panel(
        strings.configuration,
        &[
            Row::Pair(strings.profile, profile.name.clone()),
            Row::Pair(strings.server, crate::screens::servers::server_of(profile)),
            Row::Pair(strings.protocol, profile.outbound.protocol.clone()),
            Row::Gap,
            Row::Pair(strings.latency, latency),
            Row::Pair(
                strings.mode,
                crate::i18n::mode_label(state.config.routing.mode.as_str()).to_owned(),
            ),
            Row::Pair(strings.rules, state.config.routing.rules.len().to_string()),
        ],
    )
}

/// Как идёт трафик.
fn traffic(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    let connection = &state.connection;
    let scale = connection.graph_scale() as f32;

    let points = connection
        .graph
        .iter()
        .map(|point| point.up_bps.max(point.down_bps) as f32 / scale)
        .collect();

    ascii::panel(
        strings.traffic,
        &[
            Row::Pair(strings.downloaded, rate(connection.rate.down_bps)),
            Row::Pair(strings.uploaded, rate(connection.rate.up_bps)),
            Row::Chart(points),
            Row::Gap,
            Row::Pair(
                strings.total_downloaded,
                size(connection.traffic.downloaded),
            ),
            Row::Pair(strings.total_uploaded, size(connection.traffic.uploaded)),
            Row::Pair(strings.connections, connection.connections.to_string()),
        ],
    )
}

/// Строка состояния под панелью.
fn headline(state: &State) -> Element<'_, Message> {
    let connection = &state.connection;

    let (label, tone) = if connection.online {
        describe(&connection.tunnel_now())
    } else if connection.starting {
        (crate::i18n::s().service_starting.to_owned(), Tone::Busy)
    } else {
        (crate::i18n::s().daemon_offline.to_owned(), Tone::Trouble)
    };

    // Время работы уже стоит в подписи; здесь оно только мешало бы.
    let label = label
        .split_once(" · ")
        .map_or(label.clone(), |(state, _)| state.to_owned());

    Flex::row()
        .push_auto(
            text(label)
                .size(type_scale::LEAD)
                .style(iced::theme::Text::Color(tone.color(&state.palette))),
        )
        .push(crate::ui::spring())
        .push_auto(uptime(state))
        .gap(gap::SM)
        .align(Alignment::Center)
        .build()
}

/// Время работы — мелко и справа.
fn uptime(state: &State) -> Element<'_, Message> {
    let TunnelState::Connected { uptime_secs, .. } = state.connection.tunnel_now() else {
        return crate::ui::faint(&state.palette, "", type_scale::MICRO);
    };
    crate::ui::faint(
        &state.palette,
        format_uptime(uptime_secs),
        type_scale::MICRO,
    )
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
    use penguin_core::id::ProfileId;

    use super::*;

    #[test]
    fn the_column_declares_its_own_size() {
        // Растянутая панель внутри группы «по содержимому» схлопывается в
        // ноль, и на экране остаются строка состояния и кнопка, прижатые к
        // верхнему краю. Проверено на живом окне — выглядит как пустой экран.
        let state = State::default();
        let element = view(&state);
        let size = element.as_widget().size();

        assert_eq!(size.width, iced::Length::Fill);
        assert_eq!(size.height, iced::Length::Fill);
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
