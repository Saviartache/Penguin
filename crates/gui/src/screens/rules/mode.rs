//! Выбор режима: всё, белый список, чёрный список, только правила.
//!
//! Режим решает судьбу трафика, о котором правила молчат, поэтому стоит первым и
//! во всю ширину. Показывается подпись, в настройки уезжает значение
//! ([`crate::i18n::MODE_VALUES`]).

use iced::Element;
use uikit::widgets::Select;

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;

/// Режим в выпадающем списке; обёртка нужна, чтобы список показал подпись, а не `allowlist`.
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

/// Собирает верх вкладки: список режима во всю ширину.
pub fn view(state: &State) -> Element<'_, Message> {
    let current = state.config.routing.mode.as_str();

    Select::new(Choice::all(), Some(Choice(current)), |choice: Choice| {
        Message::SplitTunnel(SplitTunnelMessage::ModeSelected(choice.0.to_owned()))
    })
    .view()
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::routing::TunnelMode;

    use super::*;

    #[test]
    fn every_mode_is_shown_by_its_label() {
        for choice in Choice::all() {
            assert_eq!(choice.to_string(), crate::i18n::mode_label(choice.0));
            assert_ne!(choice.to_string(), choice.0);
        }
    }

    #[test]
    fn every_mode_of_the_router_is_offered() {
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
    fn the_select_fills_the_width() {
        let state = State::default();
        assert_eq!(
            view(&state).as_widget().size().width,
            iced::Length::Fill,
            "список режима не во всю ширину"
        );
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
