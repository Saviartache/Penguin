//! Настройки — панель терминала во всю вкладку: разделы и переключатели без
//! шапки и поиска ([`crate::screens::table::sheet`]).
//!
//! Значение и есть флажок: `[ ВКЛ  ]` / `[ ВЫКЛ ]`, переключает щелчок по строке.
//! Кнопки «Сохранить» нет: каждый флаг уезжает демону сразу, правила остаются
//! неподтверждёнными ([`crate::app::update::save`]). Темы нет: её переключает
//! кружок в шапке.
//!
//! Разделов три: «Запуск» трогает только это окно, «Сеть» — весь трафик системы,
//! «Журнал» ничего.

use iced::widget::button;
use iced::{Alignment, Element, Length};
use uikit::layout::{Flex, Sizable, Size, gap};
use uikit::tokens::ink;

use crate::app::message::{Message, SettingsMessage};
use crate::app::state::State;
use crate::screens::table::{self, CELL, ROW_GAP, ROW_PADDING, glyphs, pad};
use crate::ui;

/// Собирает экран.
pub fn view(state: &State) -> Element<'_, Message> {
    panel(state)
}

fn panel(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    let config = &state.config;

    let startup = section(
        state,
        strings.startup,
        vec![
            switch(
                state,
                strings.autostart,
                config.app.autostart,
                SettingsMessage::Autostart,
            ),
            switch(
                state,
                strings.autoconnect,
                config.app.autoconnect,
                SettingsMessage::Autoconnect,
            ),
        ],
    );

    let network = section(
        state,
        strings.network,
        vec![
            switch(
                state,
                strings.kill_switch,
                config.network.kill_switch,
                SettingsMessage::KillSwitch,
            ),
            switch(
                state,
                strings.allow_lan,
                config.network.allow_lan,
                SettingsMessage::AllowLan,
            ),
            switch(
                state,
                strings.capture_default_route,
                config.network.capture_default_route,
                SettingsMessage::CaptureDefaultRoute,
            ),
            switch(
                state,
                strings.dns_hijack,
                config.dns.hijack,
                SettingsMessage::DnsHijack,
            ),
        ],
    );

    let log = section(
        state,
        strings.log,
        vec![switch(
            state,
            strings.verbose_log,
            verbose(state),
            SettingsMessage::VerboseLog,
        )],
    );

    // Между разделами зазор больше, чем между строками.
    let body = Flex::col()
        .w(Size::FILL)
        .push_auto(startup)
        .push_auto(network)
        .push_auto(log)
        .gap(gap::MD)
        .build();

    table::sheet(
        &state.palette,
        table::scroll(body),
        crate::i18n::s().toggle_hint,
    )
}

/// Журнал подробен: любой уровень от `debug` — «включено».
fn verbose(state: &State) -> bool {
    state.config.app.log_level >= penguin_config::schema::app::LogLevel::Debug
}

/// Заголовок раздела с чертой до края и строки под ним.
fn section<'a>(
    state: &'a State,
    title: &'a str,
    rows: Vec<Element<'a, Message>>,
) -> Element<'a, Message> {
    let palette = &state.palette;

    // Пробел после заголовка: вплотную черта читается подчёркиванием.
    let head = Flex::row()
        .w(Size::FILL)
        .push_auto(glyphs(
            format!("{title} "),
            ink::level(palette, ink::SECONDARY),
        ))
        .push(table::divider(palette))
        .gap(gap::NONE)
        .align(Alignment::Center)
        .build();

    Flex::col()
        .w(Size::FILL)
        .push_auto(head)
        .extend(rows)
        .gap(ROW_GAP)
        .build()
}

/// Строка переключателя: подпись слева, значение у правого края.
fn switch<'a>(
    state: &'a State,
    label: &'a str,
    enabled: bool,
    message: fn(bool) -> SettingsMessage,
) -> Element<'a, Message> {
    let palette = &state.palette;

    // Включённое ярче: «что сейчас работает» видно боковым зрением.
    let (label_ink, value_ink) = if enabled {
        (palette.text, palette.text)
    } else {
        (
            ink::level(palette, ink::SECONDARY),
            ink::level(palette, ink::TERTIARY),
        )
    };

    let line = Flex::row()
        .w(Size::FILL)
        .push_auto(glyphs(label, label_ink))
        .push(ui::spring())
        .push_auto(glyphs(value(enabled), value_ink))
        .gap(CELL)
        .align(Alignment::Center)
        .build();

    button(line)
        .width(Length::Fill)
        .padding(ROW_PADDING)
        .style(table::row_style(enabled))
        .on_press(Message::Settings(message(!enabled)))
        .into()
}

/// Значение в скобках; обе подписи одной ширины (по самим подписям: на другом
/// языке длина другая), иначе правый край прыгает.
fn value(enabled: bool) -> String {
    let strings = crate::i18n::s();
    let width = strings.on.chars().count().max(strings.off.chars().count());
    let label = if enabled { strings.on } else { strings.off };

    format!("[ {} ]", pad(label, width))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_with_defaults() {
        let _ = view(&State::default());
    }

    #[test]
    fn the_tab_fills_the_window() {
        let size = view(&State::default()).as_widget().size();
        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn both_values_are_the_same_width() {
        assert_eq!(value(true).chars().count(), value(false).chars().count());
    }

    #[test]
    fn a_value_says_which_way_the_switch_is() {
        assert_ne!(value(true), value(false));
        assert!(value(true).contains(crate::i18n::s().on));
        assert!(value(false).contains(crate::i18n::s().off));
    }

    #[test]
    fn every_switch_is_named_by_what_it_does() {
        // Объяснений под переключателями нет: подпись — единственное, что сказано.
        for label in [
            crate::i18n::s().kill_switch,
            crate::i18n::s().allow_lan,
            crate::i18n::s().capture_default_route,
            crate::i18n::s().dns_hijack,
            crate::i18n::s().autostart,
            crate::i18n::s().autoconnect,
            crate::i18n::s().verbose_log,
        ] {
            assert!(
                label.split_whitespace().count() > 2,
                "подпись `{label}` не объясняет настройку"
            );
        }
    }

    #[test]
    fn the_theme_is_not_offered_here() {
        // Тему переключает кружок в шапке.
        let state = State::default();
        let _ = view(&state);
    }

    #[test]
    fn nothing_here_waits_for_saving() {
        let state = State {
            dirty: true,
            ..State::default()
        };
        let _ = view(&state);
    }

    #[test]
    fn every_switch_renders_in_both_positions() {
        let mut state = State::default();
        for value in [true, false] {
            state.config.app.autostart = value;
            state.config.app.autoconnect = value;
            state.config.network.kill_switch = value;
            state.config.network.allow_lan = value;
            state.config.network.capture_default_route = value;
            state.config.dns.hijack = value;
            state.config.app.log_level = if value {
                penguin_config::schema::app::LogLevel::Debug
            } else {
                penguin_config::schema::app::LogLevel::Info
            };
            let _ = view(&state);
        }
    }

    #[test]
    fn anything_more_detailed_than_info_reads_as_verbose() {
        use penguin_config::schema::app::LogLevel;

        let mut state = State::default();
        for level in [LogLevel::Error, LogLevel::Warn, LogLevel::Info] {
            state.config.app.log_level = level;
            assert!(!verbose(&state), "{level:?} — не подробный журнал");
        }
        for level in [LogLevel::Debug, LogLevel::Trace] {
            state.config.app.log_level = level;
            assert!(verbose(&state), "{level:?} — подробный журнал");
        }
    }
}
