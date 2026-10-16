//! Журнал: консоль (вкладка) и окно правила по соединению (модальное окно,
//! заменяющее тело экрана).

pub mod console;
pub mod rule;

use iced::Element;

use crate::app::message::Message;
use crate::app::state::State;

/// Собирает экран.
pub fn view(state: &State) -> Element<'_, Message> {
    match state.logs.rule.as_ref() {
        Some(window) => rule::view(state, window),
        None => console::view(state),
    }
}
