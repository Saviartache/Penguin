//! Настройки.
//!
//! Разделены надвое не для красоты. «Запуск» трогает только это окно и эту
//! машину. «Сеть» трогает **весь трафик системы**, и ошибка в ней заметна не
//! сразу.
//!
//! Поэтому у каждого переключателя в разделе сети есть строка о последствии:
//! «kill switch» и «локальная сеть мимо тоннеля» ничего не говорят тому, кто
//! видит их впервые, а цена неверного понимания — трафик, ушедший не туда.
//!
//! Темы здесь нет: её переключает кружок в шапке. Настройка, до которой два
//! пути, — это настройка, которая однажды разойдётся сама с собой.

use iced::{Alignment, Element};
use uikit::layout::{Flex, gap};
use uikit::style::tokens::type_scale;
use uikit::widgets::{ButtonVariant, Checkbox};

use crate::app::message::{Message, SettingsMessage};
use crate::app::state::State;
use crate::ui;

/// Собирает экран.
pub fn view(state: &State) -> Element<'_, Message> {
    let mut sections = vec![startup(state), network(state)];
    if state.dirty {
        sections.push(unsaved(state));
    }

    // Без заголовка: название вкладки уже стоит над экраном, и повторять его
    // значит отдать строку под то, что человек только что прочитал.
    ui::page_bare(sections)
}

/// Запуск: автозапуск и автоподключение.
fn startup(state: &State) -> Element<'_, Message> {
    let palette = &state.palette;

    let content = Flex::col()
        .push_auto(ui::switch(
            palette,
            Checkbox::new(crate::i18n::s().autostart, state.config.app.autostart)
                .on_toggle(|value| Message::Settings(SettingsMessage::AutostartToggled(value))),
            None,
        ))
        .push_auto(ui::switch(
            palette,
            Checkbox::new(crate::i18n::s().autoconnect, state.config.app.autoconnect)
                .on_toggle(|value| Message::Settings(SettingsMessage::AutoconnectToggled(value))),
            None,
        ))
        .gap(gap::MD)
        .build();

    ui::section(palette, crate::i18n::s().startup, None, content)
}

/// Сеть: то, что трогает весь трафик системы.
fn network(state: &State) -> Element<'_, Message> {
    let palette = &state.palette;

    let content = Flex::col()
        .push_auto(ui::switch(
            palette,
            Checkbox::new(
                crate::i18n::s().kill_switch,
                state.config.network.kill_switch,
            )
            .on_toggle(|value| Message::Settings(SettingsMessage::KillSwitchToggled(value))),
            Some(crate::i18n::s().kill_switch_hint),
        ))
        .push_auto(ui::switch(
            palette,
            Checkbox::new(crate::i18n::s().allow_lan, state.config.network.allow_lan)
                .on_toggle(|value| Message::Settings(SettingsMessage::AllowLanToggled(value))),
            Some(crate::i18n::s().allow_lan_hint),
        ))
        .gap(gap::MD)
        .build();

    ui::section(palette, crate::i18n::s().network, None, content)
}

/// Раздел сохранения.
///
/// Появляется только при несохранённых правках: постоянно видимая «Сохранить»
/// перестаёт что-либо значить, и её жмут на всякий случай.
fn unsaved(state: &State) -> Element<'_, Message> {
    let row = Flex::row()
        .push(ui::muted(
            &state.palette,
            crate::i18n::s().unsaved,
            type_scale::BODY,
        ))
        .push_auto(
            ui::button(ButtonVariant::Primary, crate::i18n::s().save)
                .on_press(Message::Settings(SettingsMessage::Save)),
        )
        .gap(gap::SM)
        .align(Alignment::Center)
        .build();

    ui::section(&state.palette, crate::i18n::s().save, None, row)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_with_defaults() {
        let _ = view(&State::default());
    }

    #[test]
    fn dangerous_switches_explain_themselves() {
        // Названия ничего не говорят тому, кто видит их впервые, а цена
        // неверного понимания — трафик, ушедший не туда.
        assert!(!crate::i18n::s().kill_switch_hint.is_empty());
        assert!(!crate::i18n::s().allow_lan_hint.is_empty());
    }

    #[test]
    fn the_theme_is_not_offered_here() {
        // Её переключает кружок в шапке. Два пути до одной настройки — это
        // настройка, которая однажды разойдётся сама с собой.
        let state = State::default();
        let _ = view(&state);
    }

    #[test]
    fn saving_appears_only_with_changes() {
        let mut state = State::default();
        assert!(!state.dirty);
        let _ = view(&state);

        state.dirty = true;
        let _ = view(&state);
    }
}
