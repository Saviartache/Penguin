//! Журнал работы — консоль кита без шапки (она повторяла бы подпись вкладки).
//!
//! Последнее, что произошло; полный журнал пишет служба. Консоль красит строки
//! по приметам в тексте, поэтому уровень от службы ставится в начало строки
//! ([`crate::app::state::Connection::push_log`]).

use iced::Element;
use uikit::widgets::LogTerminal;

use crate::app::message::Message;
use crate::app::state::State;

/// Собирает экран.
pub fn view(state: &State) -> Element<'_, Message> {
    LogTerminal::new(crate::i18n::s().events, &state.connection.lines)
        .without_header()
        .build()
}

#[cfg(test)]
mod tests {
    use penguin_ipc::schema::LogLevel;

    use super::*;

    #[test]
    fn an_empty_log_still_renders() {
        let state = State::default();
        assert!(state.connection.lines.is_empty());
        let _ = view(&state);
    }

    #[test]
    fn lines_carry_their_level() {
        let mut state = State::default();
        state
            .connection
            .push_log(LogLevel::Error, "неверный пароль".to_owned());

        let line = state.connection.lines.last().expect("строка есть");
        assert!(line.contains("неверный пароль"));
        assert!(
            line.starts_with(crate::i18n::s().level_error),
            "уровень не виден: {line}"
        );
    }

    #[test]
    fn the_tab_fills_the_window() {
        let size = view(&State::default()).as_widget().size();
        assert_eq!(size.width, iced::Length::Fill);
        assert_eq!(size.height, iced::Length::Fill);
    }

    #[test]
    fn a_full_log_renders() {
        let mut state = State::default();
        for step in 0..crate::app::state::LOG_CAPACITY {
            state
                .connection
                .push_log(LogLevel::Info, format!("строка {step}"));
        }
        let _ = view(&state);
    }
}
