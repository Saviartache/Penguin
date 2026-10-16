//! Экраны окна: чистые функции `view(&State) -> Element`, своего состояния нет.

pub mod compact;
pub mod logs;
pub mod rules;
pub mod servers;
pub mod settings;
pub mod table;
pub mod tunnel;

use iced::Element;

use crate::app::Screen;
use crate::app::message::Message;
use crate::app::state::State;

/// Собирает открытый экран.
pub fn view(state: &State) -> Element<'_, Message> {
    match state.screen {
        Screen::Servers => servers::view(state),
        Screen::SplitTunnel => rules::view(state),
        Screen::Logs => logs::view(state),
        Screen::Settings => settings::view(state),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_screen_renders() {
        let mut state = State::default();
        for screen in Screen::ALL {
            state.screen = screen;
            let _ = view(&state);
        }
    }
}
