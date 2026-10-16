//! Журнал работы — консоль кита без шапки (она повторяла бы подпись вкладки).
//!
//! Последнее, что произошло; полный журнал пишет служба. Консоль красит строки
//! по приметам в тексте, поэтому уровень от службы ставится в начало строки
//! ([`crate::app::state::Connection::push_log`]).
//!
//! Записи нажимаются: левая кнопка копирует, правая открывает правило. Что
//! делают кнопки, сказано плашкой в углу — догадываться не нужно.

use iced::Element;
use uikit::widgets::LogTerminal;
use uikit::widgets::log_terminal::{Status, StatusCorner};

use crate::app::message::{LogsMessage, Message};
use crate::app::state::State;

/// Собирает консоль.
pub fn view(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    let mut console = LogTerminal::new(strings.events, &state.connection.lines)
        .without_header()
        .snug_log()
        .aligned_lines()
        // Отмотанный журнал читают: новые строки его не двигают.
        .hold_scroll(state.connection.appended, strings.to_tail)
        .on_line_press(|index, button| Message::Logs(LogsMessage::LinePressed(index, button)));

    // Одна плашка в верхнем углу: «скопировано» встаёт на место подсказки, и
    // журнал под ней не сдвигается. Пустому журналу подсказка ни к чему.
    let plate = match state.logs.copied.as_ref() {
        Some((_, text)) => Some(Status::success(format!("{} · {text}", strings.copied))),
        None => (!state.connection.lines.is_empty()).then(|| Status::info(strings.log_hint)),
    };
    if let Some(plate) = plate {
        console = console.status(plate.at(StatusCorner::TopRight));
    }
    console.build()
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
