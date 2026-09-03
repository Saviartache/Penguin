//! Раздельное тоннелирование: режим, правила, новое правило, проверка.
//!
//! Самый важный экран клиента и единственный, где пользователь принимает
//! решения, а не смотрит на результат. Отсюда порядок:
//!
//! 1. **режим** — что происходит с трафиком, о котором не сказано ничего;
//! 2. **таблица** — что происходит с остальным;
//! 3. **новое правило** — как добавить ещё одно;
//! 4. **проверка** — что случится с конкретным соединением.
//!
//! Четвёртый пункт не украшение. Набор из тридцати правил без проверки —
//! чёрный ящик, и единственный способ понять, почему приложение пошло не туда,
//! — выключать правила по одному.
//!
//! Первые два стоят на вкладке, вторые два — в модальных окнах. Раньше все
//! четыре шли разделами одной прокручиваемой страницы, и таблица правил —
//! то, ради чего сюда приходят, — оказывалась зажата между формой из четырёх
//! полей и списком запущенного в полторы сотни строк. Теперь наружу не уезжает
//! ничего: вкладка занимает окно ровно один раз, а прокручивается тело таблицы
//! внутри панели.

pub mod editor;
pub mod list;
pub mod mode;
pub mod probe;

use iced::Element;

use crate::app::message::Message;
use crate::app::state::State;

/// Собирает экран.
pub fn view(state: &State) -> Element<'_, Message> {
    // Модальное окно **заменяет** тело экрана: наложения поверх содержимого в
    // `iced` нет, и так это устроено в самом ките.
    if let Some(draft) = state.split_tunnel.editor.as_ref() {
        return editor::view(state, draft);
    }
    // Новое правило важнее проверки: открыть можно только одно окно, но если
    // обе метки как-то оказались подняты, показать надо то, где человек мог
    // что-то набрать и потерять.
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
        // Наложения поверх содержимого в `iced` нет: модальное окно занимает
        // место тела экрана целиком.
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
        // Открыть можно только одно окно; если обе метки подняты, показать
        // надо то, где человек мог что-то набрать и потерять.
        let mut state = State::default();
        state.split_tunnel.editor = Some(Draft::default());
        state.split_tunnel.probe_open = true;
        let _ = view(&state);
    }
}
