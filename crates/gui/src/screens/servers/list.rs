//! Список профилей символьной таблицей.
//!
//! Таблица, а не карточки: у профиля три значения — имя, адрес, задержка, — и
//! сравнивают их **между строками**, по столбцам. Карточки ставят те же
//! значения в разных местах каждой строки, и глазу приходится искать их заново
//! на каждом сервере.
//!
//! Отсюда моноширинный набор и рамка терминала: в них столбец остаётся
//! столбцом. Активный профиль отмечен стрелкой в первой позиции — там же, где
//! её ищут в любом списке.
//!
//! Задержка показывается не ради цифры, а ради выбора: из пяти серверов
//! человек берёт ближайший, и «нет ответа» здесь такое же полезное значение,
//! как «42 мс», — оно означает «этот не трогай».
//!
//! Профиль из подписки помечается отдельно: правки в нём пропадут при
//! следующем обновлении списка, и узнать об этом лучше до правки.

use iced::widget::{container, text};
use iced::{Alignment, Element, Font, Length};
use penguin_config::schema::profile::Profile;
use penguin_core::id::ProfileId;
use uikit::layout::{Flex, Sizable, Size, gap, px};
use uikit::style::tokens::{ink, type_scale};
use uikit::widgets::ButtonVariant;

use crate::app::message::{Message, ServersMessage};
use crate::app::state::State;
use crate::ui;

/// Высота строки и кнопок в ней.
///
/// Одна на всех: разнорослые части строки читаются как случайно оказавшиеся
/// рядом, а не как одна запись.
const ROW_HEIGHT: f32 = 26.0;

/// Ширина столбца имени в знаках.
///
/// Имя профиля человек придумывает сам и делает коротким; двадцать знаков
/// хватает с запасом, а всё, что длиннее, важнее обрезать, чем сдвинуть за
/// ним остальные столбцы.
const NAME_WIDTH: usize = 20;

/// Ширина столбца задержки в знаках.
const LATENCY_WIDTH: usize = 8;

/// Собирает содержимое вкладки.
///
/// Страницу с прокруткой оборачивает вокруг него экран
/// ([`super::view`]) — здесь второй такой обёртки быть не должно. Прокрутка
/// объявляет себя растянутой по высоте, а вложенная в чужую страницу
/// растянутая группа схлопывается в ноль: вкладка оказывается пустой.
pub fn view(state: &State) -> Element<'_, Message> {
    Flex::col()
        .push_auto(toolbar(state))
        .push_auto(table(state))
        .gap(gap::MD)
        .build()
}

/// Две кнопки над таблицей.
fn toolbar(state: &State) -> Element<'_, Message> {
    let mut probe = ui::button(ButtonVariant::Secondary, crate::i18n::s().probe).h(px(ROW_HEIGHT));
    // Пока идёт проверка, повторное нажатие сбросило бы уже собранные
    // задержки и началось бы заново.
    if !state.servers.probing {
        probe = probe.on_press(Message::Servers(ServersMessage::Probe));
    }

    Flex::row()
        .push_auto(
            ui::button(ButtonVariant::Primary, crate::i18n::s().add_server)
                .h(px(ROW_HEIGHT))
                .on_press(Message::Servers(ServersMessage::EditorOpened(None))),
        )
        .push_auto(probe)
        .push(ui::spring())
        .gap(gap::SM)
        .align(Alignment::Center)
        .build()
}

/// Таблица профилей в рамке терминала.
fn table(state: &State) -> Element<'_, Message> {
    let palette = &state.palette;
    let profiles = &state.config.profiles;

    let body: Element<'_, Message> = if profiles.is_empty() {
        ui::empty(palette, crate::i18n::s().no_profiles)
    } else {
        let active = state.config.active().map(|profile| profile.id.clone());
        let rows = profiles
            .iter()
            .map(|profile| row(state, profile, active.as_ref()))
            .collect::<Vec<_>>();

        Flex::col()
            .w(Size::FILL)
            .push_auto(header(state))
            .extend(rows)
            .gap(gap::XS)
            .build()
    };

    container(body)
        .width(Length::Fill)
        .padding(gap::MD)
        .style(uikit::style::container::log_terminal_viewport as fn(&iced::Theme) -> _)
        .into()
}

/// Шапка таблицы — имена столбцов.
fn header(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();

    Flex::row()
        .push_auto(mono(
            state,
            pad(&format!("  {}", strings.profile), NAME_WIDTH + 2),
            ink::TERTIARY,
        ))
        .push_auto(mono(state, strings.server.to_owned(), ink::TERTIARY))
        .push(ui::spring())
        .push_auto(mono(
            state,
            pad(strings.latency, LATENCY_WIDTH),
            ink::TERTIARY,
        ))
        .gap(gap::SM)
        .align(Alignment::Center)
        .build()
}

/// Строка профиля.
fn row<'a>(
    state: &'a State,
    profile: &'a Profile,
    active: Option<&ProfileId>,
) -> Element<'a, Message> {
    let id = profile.id.to_string();
    let is_active = active == Some(&profile.id);

    // Стрелка в первой позиции — там, где её ищут в любом списке. Пробел
    // вместо неё у остальных: без него столбец имени съезжал бы на знак.
    let marker = if is_active { "▶" } else { " " };
    let name = clip(&profile.name, NAME_WIDTH);
    // Активный ярче остальных: список читают ради вопроса «какой сейчас», и
    // ответ на него должен находиться боковым зрением.
    let level = if is_active { 1.0 } else { ink::SECONDARY };

    let mut line = Flex::row()
        .push_auto(mono(
            state,
            format!("{marker} {}", pad(&name, NAME_WIDTH)),
            level,
        ))
        .push_auto(mono(
            state,
            crate::screens::servers::server_of(profile),
            ink::SECONDARY,
        ))
        .push(ui::spring());

    if profile.is_managed() {
        // Правки в таком профиле пропадут при обновлении подписки.
        line = line.push_auto(mono(
            state,
            crate::i18n::s().managed.to_owned(),
            ink::TERTIARY,
        ));
    }

    line = line.push_auto(mono(
        state,
        pad(&latency(state, &profile.id), LATENCY_WIDTH),
        ink::SECONDARY,
    ));

    let select_id = id.clone();
    // Активный профиль выбирать некуда: кнопка без последствий читается как
    // сломанная.
    if !is_active {
        line = line.push_auto(
            ui::button(ButtonVariant::Secondary, crate::i18n::s().select)
                .h(px(ROW_HEIGHT))
                .on_press(Message::Servers(ServersMessage::Select(select_id))),
        );
    }

    line.push_auto(
        ui::button(ButtonVariant::Neutral, crate::i18n::s().edit)
            .h(px(ROW_HEIGHT))
            .on_press(Message::Servers(ServersMessage::EditorOpened(Some(id)))),
    )
    .gap(gap::SM)
    .align(Alignment::Center)
    .build()
}

/// Задержка до сервера словом или цифрой.
fn latency(state: &State, id: &ProfileId) -> String {
    let strings = crate::i18n::s();
    if state.servers.probing {
        return strings.probing.to_owned();
    }

    state
        .servers
        .latencies
        .iter()
        .find(|(profile, _)| profile == id.as_str())
        .map_or_else(
            || "—".to_owned(),
            |(_, rtt)| match rtt {
                Some(rtt) => format!("{rtt} {}", strings.millis),
                // «Нет ответа» — это тоже ответ: он означает «этот не трогай».
                None => strings.no_answer.to_owned(),
            },
        )
}

/// Моноширинная ячейка заданной приглушённости.
fn mono<'a>(state: &State, value: String, level: f32) -> Element<'a, Message> {
    text(value)
        .font(Font::MONOSPACE)
        .size(type_scale::BODY)
        .color(ink::level(&state.palette, level))
        .into()
}

/// Дополняет строку пробелами до ширины столбца.
///
/// Свободная функция с тестом: столбец, съехавший на знак, — единственное, что
/// видно в таблице, и последнее, что находится глазами в коде.
fn pad(value: &str, width: usize) -> String {
    let tail = width.saturating_sub(value.chars().count());
    format!("{value}{}", " ".repeat(tail))
}

/// Обрезает строку по знакам, а не по байтам.
fn clip(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_owned();
    }
    value
        .chars()
        .take(width.saturating_sub(1))
        .collect::<String>()
        + "…"
}

#[cfg(test)]
mod tests {
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
        // Пустая рамка читается как «не загрузилось».
        let state = State::default();
        assert!(state.config.profiles.is_empty());
        let _ = view(&state);
    }

    #[test]
    fn the_tab_does_not_wrap_a_page_of_its_own() {
        // Страницу с прокруткой ставит экран; вторая такая же внутри неё
        // объявляет себя растянутой по высоте и схлопывается в ноль — вкладка
        // оказывается пустой. Проверено на живом окне.
        let mut state = State::default();
        state.config.profiles.push(profile("home"));

        let element = view(&state);
        assert_ne!(
            element.as_widget().size().height,
            Length::Fill,
            "вкладка объявила себя растянутой — снаружи её схлопнет"
        );
    }

    #[test]
    fn columns_keep_their_width() {
        // Таблицу читают по столбцам; съехавший на знак столбец рушит весь
        // смысл затеи.
        assert_eq!(pad("source", NAME_WIDTH).chars().count(), NAME_WIDTH);
        assert_eq!(pad("", NAME_WIDTH).chars().count(), NAME_WIDTH);
        assert_eq!(pad("90 мс", LATENCY_WIDTH).chars().count(), LATENCY_WIDTH);
    }

    #[test]
    fn a_long_name_is_clipped_not_pushed_through() {
        // Иначе длинное имя сдвинуло бы за собой все остальные столбцы.
        let long = "и".repeat(100);
        assert_eq!(clip(&long, NAME_WIDTH).chars().count(), NAME_WIDTH);
        assert!(clip(&long, NAME_WIDTH).ends_with('…'));
    }

    #[test]
    fn a_name_that_fits_is_left_alone() {
        assert_eq!(clip("source", NAME_WIDTH), "source");
    }

    #[test]
    fn the_active_profile_is_marked() {
        let mut state = State::default();
        state.config.profiles.push(profile("home"));
        state.config.profiles.push(profile("work"));
        let _ = view(&state);
    }

    #[test]
    fn a_probe_in_flight_shows_itself_in_every_row() {
        // Пустая клетка во время проверки читается как «не ответил».
        let mut state = State::default();
        state.config.profiles.push(profile("home"));
        state.servers.probing = true;

        assert_eq!(
            latency(&state, &ProfileId::new("home")),
            crate::i18n::s().probing
        );
    }

    #[test]
    fn no_answer_is_a_value_too() {
        // Оно означает «этот не трогай» и полезно ровно так же, как цифра.
        let mut state = State::default();
        state.servers.latencies.push(("home".to_owned(), None));

        assert_eq!(
            latency(&state, &ProfileId::new("home")),
            crate::i18n::s().no_answer
        );
    }
}
