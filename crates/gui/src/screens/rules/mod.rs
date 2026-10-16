//! Раздельное тоннелирование: группы и «всё остальное» (вкладка), окно группы и
//! проверка (модальные окна, заменяющие тело экрана).

pub mod describe;
pub mod editor;
pub mod list;
pub mod mode;
pub mod probe;
pub mod values;

use iced::Element;

use crate::app::message::Message;
use crate::app::state::State;

/// Собирает экран.
pub fn view(state: &State) -> Element<'_, Message> {
    if let Some(draft) = state.split_tunnel.editor.as_ref() {
        return editor::view(state, draft);
    }
    // Новое правило важнее проверки: терять набранное хуже.
    if state.split_tunnel.probe_open {
        return probe::view(state);
    }

    list::view(state)
}

#[cfg(test)]
mod tests {
    use crate::forms::rule::Draft;

    use super::*;

    #[test]
    fn renders_the_table_when_no_window_is_open() {
        let state = State::default();
        assert!(state.split_tunnel.editor.is_none());
        assert!(!state.split_tunnel.probe_open);
        let _ = view(&state);
    }

    #[test]
    fn the_editor_replaces_the_table() {
        let mut state = State::default();
        state.split_tunnel.editor = Some(Draft::default());
        let _ = view(&state);
    }

    #[test]
    fn the_probe_replaces_the_table() {
        let mut state = State::default();
        state.split_tunnel.probe_open = true;
        let _ = view(&state);
    }

    #[test]
    fn the_editor_wins_over_the_probe() {
        let mut state = State::default();
        state.split_tunnel.editor = Some(Draft::default());
        state.split_tunnel.probe_open = true;
        let _ = view(&state);
    }
}
