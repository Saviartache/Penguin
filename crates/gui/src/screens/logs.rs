//! Журнал работы — символьной консолью кита.
//!
//! Показывает последнее, что произошло; полный журнал пишет служба в файл.
//! Здесь он нужен для одного вопроса — «почему сейчас не подключилось», — и
//! ответ на него всегда в последних строках.
//!
//! Уровень строки приходит **от службы**, а не угадывается по словам. Панель
//! красит строки по приметам в тексте, и это разумно там, где журнал приходит
//! чужой и без разметки; у нас уровень известен точно, поэтому он ставится в
//! начало строки сам — тогда и примета верная, и человек видит уровень
//! глазами.

use iced::Element;
use uikit::widgets::LogTerminal;

use crate::app::message::Message;
use crate::app::state::State;

/// Собирает экран.
pub fn view(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();

    // Без плашек по углам: журнал открывают ради строк, а состояние службы
    // уже стоит в компактном окне, откуда сюда и пришли. Дублировать его
    // поверх собственно журнала значит отнимать место у того, ради чего он
    // открыт.
    LogTerminal::new(strings.events, &state.connection.lines).build()
}

#[cfg(test)]
mod tests {
    use penguin_ipc::schema::LogLevel;

    use super::*;

    #[test]
    fn an_empty_log_still_renders() {
        // Пустой журнал — обычное состояние первых секунд.
        let state = State::default();
        assert!(state.connection.lines.is_empty());
        let _ = view(&state);
    }

    #[test]
    fn lines_carry_their_level() {
        // Панель красит строки по приметам в тексте; без уровня в начале
        // строки ошибка выглядела бы как обычная запись.
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
