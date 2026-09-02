//! Выбор режима: всё, белый список, чёрный список, только правила.
//!
//! В списке показываются подписи, а в настройки уезжает значение
//! ([`crate::i18n::MODE_VALUES`]). Разделены они не ради перевода: значения
//! читает маршрутизатор и они не меняются никогда, а подписи меняются каждый
//! раз, когда выясняется, что человек понял их не так.
//!
//! Подсказка под списком меняется вместе с выбором и объясняет не «что такое
//! режим», а что сейчас происходит с трафиком. Это не подсказка для новичка:
//! «белый список» и «чёрный список» в разных клиентах означают
//! противоположные вещи, и цена ошибки — весь трафик мимо тоннеля.

use iced::Element;
use uikit::widgets::Select;

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::ui;

/// Режим в выпадающем списке.
///
/// Обёртка нужна затем, что список показывает варианты через `ToString`: без
/// неё пользователь читал бы в нём `allowlist`, а не «Только выбранное — в
/// тоннель».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Choice(pub &'static str);

impl Choice {
    /// Все режимы в порядке показа.
    pub fn all() -> Vec<Self> {
        crate::i18n::MODE_VALUES.map(Self).to_vec()
    }
}

impl std::fmt::Display for Choice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(crate::i18n::mode_label(self.0))
    }
}

/// Собирает раздел выбора режима.
pub fn view(state: &State) -> Element<'_, Message> {
    let current = state.config.routing.mode.as_str();

    let select = Select::new(Choice::all(), Some(Choice(current)), |choice: Choice| {
        Message::SplitTunnel(SplitTunnelMessage::ModeSelected(choice.0.to_owned()))
    })
    .view();

    ui::section(
        &state.palette,
        crate::i18n::s().mode,
        Some(crate::i18n::mode_hint(current)),
        select,
    )
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::routing::TunnelMode;

    use super::*;

    #[test]
    fn every_mode_is_shown_by_its_label() {
        // Без обёртки пользователь читал бы в списке `allowlist`.
        for choice in Choice::all() {
            assert_eq!(choice.to_string(), crate::i18n::mode_label(choice.0));
            assert_ne!(choice.to_string(), choice.0);
        }
    }

    #[test]
    fn every_mode_of_the_router_is_offered() {
        // Режим, которого нет в списке, но есть в файле, оставил бы список
        // пустым и режим неизменяемым.
        let offered: Vec<&str> = Choice::all().into_iter().map(|choice| choice.0).collect();
        for mode in [
            TunnelMode::Full,
            TunnelMode::Allowlist,
            TunnelMode::Blocklist,
            TunnelMode::Off,
        ] {
            assert!(
                offered.contains(&mode.as_str()),
                "режим `{mode:?}` не предлагается"
            );
        }
    }

    #[test]
    fn the_hint_matches_what_the_router_does() {
        // Объяснение и поведение маршрутизатора обязаны совпадать, а расходятся
        // они молча.
        assert!(TunnelMode::Full.defaults_to_tunnel());
        assert!(crate::i18n::mode_hint("full").contains("Весь трафик"));

        assert!(!TunnelMode::Allowlist.defaults_to_tunnel());
        assert!(crate::i18n::mode_hint("allowlist").contains("только"));

        assert!(!TunnelMode::Off.defaults_to_tunnel());
        assert!(crate::i18n::mode_hint("off").contains("выключен"));
    }

    #[test]
    fn renders_in_every_mode() {
        let mut state = State::default();
        for mode in [
            TunnelMode::Full,
            TunnelMode::Allowlist,
            TunnelMode::Blocklist,
            TunnelMode::Off,
        ] {
            state.config.routing.mode = mode;
            let _ = view(&state);
        }
    }
}
