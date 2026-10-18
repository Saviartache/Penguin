//! Список профилей — таблица терминала во всю вкладку.
//!
//! Таблица общая ([`crate::screens::table`]), здесь только столбцы. Выбор —
//! щелчок по строке, выбранная помечена волной: знак в первом столбце сдвинул
//! бы строку (нет в шрифте кита, см. [`crate::console`]). Задержка нужна для
//! выбора, «нет ответа» значит «этот не трогай». Флаг страны — картинка
//! ([`crate::flags`]); пока страна неизвестна, место под него пустое.

use iced::widget::{Space, button};
use iced::{Alignment, Element, Length};
use penguin_config::schema::profile::Profile;
use penguin_core::id::ProfileId;
use uikit::layout::{Flex, Sizable, Size, gap, px};
use uikit::tokens::ink;
use uikit::widgets::ButtonVariant;

use crate::app::TAB_GAP;
use crate::app::message::{Message, ServersMessage};
use crate::app::state::State;
use crate::flags;
use crate::screens::table::{
    self, BUTTON_HEIGHT, CELL, DASH, ROW_GAP, ROW_PADDING, cell, glyphs, lpad, pad,
};
use crate::ui;

/// Ширина столбца имени в знаках; длинное режется, а не двигает остальное.
const NAME_WIDTH: usize = 18;

/// Ширина столбца адреса в знаках.
const SERVER_WIDTH: usize = 26;

/// Ширина столбца протокола: самое длинное имя (`shadowsocks`) — 11 знаков.
const PROTOCOL_WIDTH: usize = 12;

/// Ширина столбца задержки в знаках.
const LATENCY_WIDTH: usize = 8;

/// Ширина столбца действия в точках.
const ACTION_WIDTH: f32 = 76.0;

/// Ширина действия «пинг» в точках: подпись короче.
const PING_WIDTH: f32 = 56.0;

/// Собирает вкладку: кнопки и панель под ними; прокручивается список внутри панели.
pub fn view(state: &State) -> Element<'_, Message> {
    Flex::col()
        .w(Size::FILL)
        .h(Size::FILL)
        .push_auto(toolbar(state))
        .push(panel(state))
        .gap(TAB_GAP)
        .build()
}

fn toolbar(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    // Во время прогона та же кнопка его останавливает.
    let probe = if state.servers.probe.is_running() {
        ui::button(ButtonVariant::Secondary, strings.probe_stop)
            .on_press(Message::Servers(ServersMessage::ProbeStopped))
    } else {
        ui::button(ButtonVariant::Secondary, strings.probe)
            .on_press(Message::Servers(ServersMessage::Probe))
    }
    .h(px(BUTTON_HEIGHT));

    Flex::row()
        .push_auto(
            ui::button(ButtonVariant::Primary, crate::i18n::s().add_server)
                .h(px(BUTTON_HEIGHT))
                .on_press(Message::Servers(ServersMessage::PickerOpened)),
        )
        .push_auto(probe)
        .push(ui::spring())
        .gap(gap::SM)
        .align(Alignment::Center)
        .build()
}

fn panel(state: &State) -> Element<'_, Message> {
    table::panel(
        &state.palette,
        table::search(crate::i18n::s().search, &state.servers.search, |value| {
            Message::Servers(ServersMessage::SearchChanged(value))
        }),
        head(state),
        rows(state),
        crate::i18n::s().select_hint,
    )
}

/// Шапка с тем же отступом и местом под действие, что у строки.
fn head(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    let dim = ink::level(&state.palette, ink::TERTIARY);

    let titles = columns(
        flags::slot(None),
        glyphs(pad(strings.profile, NAME_WIDTH), dim),
        glyphs(pad(strings.server, SERVER_WIDTH), dim),
        glyphs(pad(strings.protocol, PROTOCOL_WIDTH), dim),
        None,
        glyphs(lpad(strings.latency, LATENCY_WIDTH), dim),
    );

    Flex::row()
        .w(Size::FILL)
        .push(
            iced::widget::container(titles)
                .padding(ROW_PADDING)
                .width(Length::Fill),
        )
        .push_auto(Space::new().width(Length::Fixed(PING_WIDTH + ACTION_WIDTH)))
        .gap(gap::NONE)
        .build()
}

fn rows(state: &State) -> Element<'_, Message> {
    let profiles = &state.config.profiles;
    if profiles.is_empty() {
        return table::empty(&state.palette, crate::i18n::s().no_profiles);
    }

    let shown: Vec<&Profile> = profiles
        .iter()
        .filter(|profile| found(profile, &state.servers.search))
        .collect();
    if shown.is_empty() {
        return table::empty(&state.palette, crate::i18n::s().nothing_found);
    }

    let active = state.config.active().map(|profile| profile.id.clone());
    let list = Flex::col()
        .w(Size::FILL)
        .extend(
            shown
                .into_iter()
                .map(|profile| row(state, profile, active.as_ref())),
        )
        .gap(ROW_GAP)
        .build();

    table::scroll(list)
}

/// Подходит ли профиль под поиск: по имени, адресу и протоколу.
fn found(profile: &Profile, query: &str) -> bool {
    let server = crate::screens::servers::server_of(profile).unwrap_or_default();

    table::matches(
        query,
        &[
            &profile.name,
            profile.id.as_str(),
            server,
            &profile.outbound.protocol,
        ],
    )
}

/// Строка профиля: сама выбирает, кнопка справа открывает правку.
fn row<'a>(
    state: &'a State,
    profile: &'a Profile,
    active: Option<&ProfileId>,
) -> Element<'a, Message> {
    let id = profile.id.to_string();
    let selected = active == Some(&profile.id);
    let palette = &state.palette;

    // Выбранный ярче: «какой сейчас» должно находиться боковым зрением.
    let (name_ink, server_ink) = if selected {
        (palette.text, ink::level(palette, ink::SECONDARY))
    } else {
        (
            ink::level(palette, ink::SECONDARY),
            ink::level(palette, ink::TERTIARY),
        )
    };
    let protocol_ink = ink::level(palette, ink::TERTIARY);
    // Правки в профиле подписки пропадут при её обновлении.
    let managed = profile
        .is_managed()
        .then(|| glyphs(crate::i18n::s().managed, ink::level(palette, ink::TERTIARY)));

    let server = crate::screens::servers::server_of(profile)
        .map_or_else(|| DASH.to_string(), |server| cell(server, SERVER_WIDTH));

    let cells = columns(
        flags::slot(state.servers.countries.flag(profile)),
        glyphs(cell(&profile.name, NAME_WIDTH), name_ink),
        glyphs(pad(&server, SERVER_WIDTH), server_ink),
        glyphs(
            cell(&profile.outbound.protocol, PROTOCOL_WIDTH),
            protocol_ink,
        ),
        managed,
        glyphs(
            lpad(&latency(state, &profile.id), LATENCY_WIDTH),
            ink::level(palette, ink::SECONDARY),
        ),
    );

    let mut select = button(cells)
        .width(Length::Fill)
        .padding(ROW_PADDING)
        .style(table::row_style(selected));
    // Нажатие без последствий читается как сломанное.
    if !selected {
        select = select.on_press(Message::Servers(ServersMessage::Select(id.clone())));
    }

    Flex::row()
        .push(select)
        .push_auto(table::action(
            crate::i18n::s().ping,
            PING_WIDTH,
            Message::Servers(ServersMessage::ProbeOne(id.clone())),
        ))
        .push_auto(table::action(
            crate::i18n::s().edit,
            ACTION_WIDTH,
            Message::Servers(ServersMessage::EditorOpened(id)),
        ))
        .gap(gap::NONE)
        .align(Alignment::Center)
        .build()
}

/// Ряд ячеек — общий для шапки и строк, чтобы столбцы не разъезжались.
fn columns<'a, Message: 'a>(
    flag: Element<'a, Message>,
    name: Element<'a, Message>,
    server: Element<'a, Message>,
    protocol: Element<'a, Message>,
    managed: Option<Element<'a, Message>>,
    latency: Element<'a, Message>,
) -> Element<'a, Message> {
    let mut line = Flex::row()
        .w(Size::FILL)
        .push_auto(flag)
        .push_auto(name)
        .push_auto(server)
        .push_auto(protocol);

    // Метка подписки стоит до распорки, иначе задержка съезжает на таких строках.
    if let Some(managed) = managed {
        line = line.push_auto(managed);
    }

    line.push(ui::spring())
        .push_auto(latency)
        .gap(CELL)
        .align(Alignment::Center)
        .build()
}

fn latency(state: &State, id: &ProfileId) -> String {
    let strings = crate::i18n::s();
    if state.servers.probe.current() == Some(id.as_str()) {
        return strings.probing.to_owned();
    }

    state
        .servers
        .latencies
        .iter()
        .find(|(profile, _)| profile == id.as_str())
        .map_or_else(
            || DASH.to_string(),
            |(_, rtt)| match rtt {
                Some(rtt) => format!("{rtt} {}", strings.millis),
                None => strings.no_answer.to_owned(),
            },
        )
}

#[cfg(test)]
mod tests {
    use iced::Color;
    use penguin_config::schema::outbound::RawOutbound;
    use serde_json::json;

    use super::*;

    fn profile(name: &str) -> Profile {
        Profile::new(
            name,
            name,
            RawOutbound::new("hysteria2", json!({ "server": "example.com:443" })),
        )
    }

    #[test]
    fn an_empty_list_says_so() {
        let state = State::default();
        assert!(state.config.profiles.is_empty());
        let _ = view(&state);
    }

    #[test]
    fn the_tab_fills_the_panel() {
        let mut state = State::default();
        state.config.profiles.push(profile("home"));

        let size = view(&state).as_widget().size();
        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn columns_keep_their_width() {
        assert_eq!(pad("source", NAME_WIDTH).chars().count(), NAME_WIDTH);
        assert_eq!(
            cell("hysteria2", PROTOCOL_WIDTH).chars().count(),
            PROTOCOL_WIDTH
        );
        assert_eq!(lpad("90 мс", LATENCY_WIDTH).chars().count(), LATENCY_WIDTH);
    }

    #[test]
    fn the_chosen_row_never_shifts_its_columns() {
        let dim = Color::WHITE;
        let head: Element<'_, Message> = columns(
            flags::slot(None),
            glyphs(pad("ПРОФИЛЬ", NAME_WIDTH), dim),
            glyphs(pad("СЕРВЕР", SERVER_WIDTH), dim),
            glyphs(pad("ПРОТОКОЛ", PROTOCOL_WIDTH), dim),
            None,
            glyphs(lpad("ЗАДЕРЖКА", LATENCY_WIDTH), dim),
        );
        let row: Element<'_, Message> = columns(
            flags::slot(crate::flags::Flag::of("jp")),
            glyphs(pad("source", NAME_WIDTH), dim),
            glyphs(pad("example.com:443", SERVER_WIDTH), dim),
            glyphs(pad("hysteria2", PROTOCOL_WIDTH), dim),
            None,
            glyphs(lpad("42 мс", LATENCY_WIDTH), dim),
        );

        assert_eq!(head.as_widget().size(), row.as_widget().size());
    }

    #[test]
    fn the_chosen_row_is_marked_and_the_rest_are_not() {
        let mut state = State::default();
        state.config.profiles.push(profile("home"));
        state.config.profiles.push(profile("work"));
        state.config.active_profile = Some(ProfileId::new("work"));

        let _ = view(&state);
    }

    #[test]
    fn search_finds_a_profile_by_any_of_its_columns() {
        let profile = profile("home");
        assert!(found(&profile, ""));
        assert!(found(&profile, "HOME"));
        assert!(found(&profile, "example.com"));
        assert!(found(&profile, "hysteria"));
        assert!(!found(&profile, "нет такого"));
    }

    #[test]
    fn a_search_that_finds_nothing_says_so() {
        let mut state = State::default();
        state.config.profiles.push(profile("home"));
        state.servers.search = "нет такого".to_owned();
        let _ = view(&state);
    }

    #[test]
    fn the_protocol_column_holds_the_names_that_are_coming() {
        for protocol in ["hysteria2", "shadowsocks", "wireguard", "vless"] {
            assert!(
                protocol.chars().count() <= PROTOCOL_WIDTH,
                "`{protocol}` не помещается в столбец"
            );
        }
    }

    #[test]
    fn a_profile_without_an_address_shows_a_dash_not_its_protocol() {
        let profile = Profile::new("x", "x", RawOutbound::new("vless", json!({})));
        assert_eq!(crate::screens::servers::server_of(&profile), None);
    }

    #[test]
    fn only_the_row_being_probed_shows_progress() {
        let mut state = State::default();
        state.config.profiles.push(profile("home"));
        state
            .servers
            .probe
            .start(["home".to_owned(), "work".to_owned()]);

        assert_eq!(
            latency(&state, &ProfileId::new("home")),
            crate::i18n::s().probing
        );
        assert_eq!(latency(&state, &ProfileId::new("work")), DASH.to_string());
    }

    #[test]
    fn no_answer_is_a_value_too() {
        let mut state = State::default();
        state.servers.latencies.push(("home".to_owned(), None));

        assert_eq!(
            latency(&state, &ProfileId::new("home")),
            crate::i18n::s().no_answer
        );
    }

    #[test]
    fn an_unknown_latency_is_a_dash_the_font_has() {
        let state = State::default();
        assert_eq!(latency(&state, &ProfileId::new("home")), DASH.to_string());
    }
}
