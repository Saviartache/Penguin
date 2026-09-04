//! Настройки — символьная панель терминала во всю вкладку.
//!
//! Тот же прямоугольник консоли, что у серверов и правил, но не таблица:
//! настройки — это четыре переключателя, а не список записей. Столбцов, по
//! которым сравнивают строки, здесь нет, сравнивать нечего, и потому нет ни
//! шапки, ни поиска — только разделы и строки под ними
//! ([`crate::screens::table::sheet`]).
//!
//! Строки набраны, как вывод `MEM`: подпись слева, значение у правого края,
//! заголовок раздела с чертой до края. Флажка нет — значение и есть флажок:
//! `[ ВКЛ  ]` или `[ ВЫКЛ ]`, а переключает щелчок по строке, как в списке
//! правил. Квадратик флажка в такой панели был бы единственным на весь экран
//! элементом не из терминала.
//!
//! Значения выровнены по правому краю не ради красоты: вопрос, с которым сюда
//! приходят, — «что из этого сейчас включено», и ответ на него читают одним
//! движением сверху вниз по столбцу, а не по концам строк разной длины.
//!
//! Строк-объяснений под переключателями нет: подписи сказаны целыми
//! предложениями («Блокировать трафик при разрыве тоннеля»), и абзац под
//! каждым пересказывал бы подпись второй раз, разгоняя четыре строки на
//! пол-экрана.
//!
//! Кнопки «Сохранить» здесь нет: каждый переключатель уезжает демону сразу.
//! Настройка — это один флаг, а не набор, который собирают и подтверждают
//! целиком; щелчок, после которого ничего не произошло, пока не нажата вторая
//! кнопка, читается как несработавший, и человек щёлкает ещё раз. Правила при
//! этом остаются неподтверждёнными — см. [`crate::app::update::save`].
//!
//! Темы здесь нет: её переключает кружок в шапке. Настройка, до которой два
//! пути, — это настройка, которая однажды разойдётся сама с собой.
//!
//! # Почему разделов два
//!
//! «Запуск» трогает только это окно и эту машину. «Сеть» трогает **весь трафик
//! системы**, и ошибка в ней заметна не сразу.

use iced::widget::button;
use iced::{Alignment, Element, Length};
use uikit::layout::{Flex, Sizable, Size, gap};
use uikit::style::tokens::ink;

use crate::app::message::{Message, SettingsMessage};
use crate::app::state::State;
use crate::screens::table::{self, CELL, ROW_GAP, ROW_PADDING, glyphs, pad};
use crate::ui;

/// Собирает экран.
///
/// Одна панель во всю вкладку: ряда кнопок над ней нет, потому что нет и
/// кнопок — переключатели сохраняются сами.
pub fn view(state: &State) -> Element<'_, Message> {
    panel(state)
}

/// Панель терминала: разделы и переключатели.
fn panel(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    let palette = &state.palette;

    let startup = section(
        state,
        strings.startup,
        vec![
            switch(
                state,
                strings.autostart,
                state.config.app.autostart,
                SettingsMessage::Autostart,
            ),
            switch(
                state,
                strings.autoconnect,
                state.config.app.autoconnect,
                SettingsMessage::Autoconnect,
            ),
        ],
    );

    let network = section(
        state,
        strings.network,
        vec![
            switch(
                state,
                strings.kill_switch,
                state.config.network.kill_switch,
                SettingsMessage::KillSwitch,
            ),
            switch(
                state,
                strings.allow_lan,
                state.config.network.allow_lan,
                SettingsMessage::AllowLan,
            ),
        ],
    );

    let body = Flex::col()
        .w(Size::FILL)
        .push_auto(startup)
        .push_auto(network)
        // Между разделами больше, чем между строками: иначе четыре
        // переключателя читаются одним списком, и деление теряет смысл.
        .gap(gap::MD)
        .build();

    // Прокрутка при четырёх строках не нужна и не видна, но заводится сразу:
    // настройка добавляется одной строкой, а спохватываются об этом уже тогда,
    // когда нижняя ушла под край панели.
    table::sheet(palette, table::scroll(body), crate::i18n::s().toggle_hint)
}

/// Заголовок раздела с чертой до края и строки под ним.
fn section<'a>(
    state: &'a State,
    title: &'a str,
    rows: Vec<Element<'a, Message>>,
) -> Element<'a, Message> {
    let palette = &state.palette;

    let head = Flex::row()
        .w(Size::FILL)
        // Пробел после заголовка: черта, начинающаяся вплотную к букве,
        // читается как подчёркивание, а не как кромка раздела.
        .push_auto(glyphs(
            format!("{title} "),
            ink::level(palette, ink::SECONDARY),
        ))
        .push(table::divider(palette))
        .gap(gap::NONE)
        .align(Alignment::Center)
        .build();

    Flex::col()
        .w(Size::FILL)
        .push_auto(head)
        .extend(rows)
        .gap(ROW_GAP)
        .build()
}

/// Строка переключателя: подпись слева, значение у правого края.
fn switch<'a>(
    state: &'a State,
    label: &'a str,
    enabled: bool,
    message: fn(bool) -> SettingsMessage,
) -> Element<'a, Message> {
    let palette = &state.palette;

    // Включённое ярче выключенного: вопрос, с которым сюда приходят, — «что из
    // этого сейчас работает», и ответ должен находиться боковым зрением.
    let (label_ink, value_ink) = if enabled {
        (palette.text, palette.text)
    } else {
        (
            ink::level(palette, ink::SECONDARY),
            ink::level(palette, ink::TERTIARY),
        )
    };

    let line = Flex::row()
        .w(Size::FILL)
        .push_auto(glyphs(label.to_owned(), label_ink))
        .push(ui::spring())
        .push_auto(glyphs(value(enabled), value_ink))
        .gap(CELL)
        .align(Alignment::Center)
        .build();

    button(line)
        .width(Length::Fill)
        .padding(ROW_PADDING)
        // Волна помечает включённое — та же, что на выбранном профиле и на
        // работающем правиле.
        .style(table::row_style(enabled))
        .on_press(Message::Settings(message(!enabled)))
        .into()
}

/// Значение переключателя в скобках, как пункт меню терминала.
///
/// Обе подписи набираются одной ширины, иначе правый край столбца значений
/// прыгает от строки к строке, а читают его именно как столбец. Ширина берётся
/// из самих подписей: на другом языке они другой длины, и подобранное число
/// разошлось бы с ними молча.
fn value(enabled: bool) -> String {
    let strings = crate::i18n::s();
    let width = strings.on.chars().count().max(strings.off.chars().count());
    let label = if enabled { strings.on } else { strings.off };

    format!("[ {} ]", pad(label, width))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_with_defaults() {
        let _ = view(&State::default());
    }

    #[test]
    fn the_tab_fills_the_window() {
        // Панель — окно терминала: она занимает вкладку целиком, а
        // прокручивается тело внутри неё. Страницы с прокруткой вокруг нет.
        let size = view(&State::default()).as_widget().size();
        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn both_values_are_the_same_width() {
        // Правый край столбца значений не должен прыгать от строки к строке:
        // читают его именно как столбец.
        assert_eq!(value(true).chars().count(), value(false).chars().count());
    }

    #[test]
    fn a_value_says_which_way_the_switch_is() {
        // Значение и есть флажок; не различив их, человек не поймёт состояние.
        assert_ne!(value(true), value(false));
        assert!(value(true).contains(crate::i18n::s().on));
        assert!(value(false).contains(crate::i18n::s().off));
    }

    #[test]
    fn every_switch_is_named_by_what_it_does() {
        // Строки-объяснения под переключателями убраны, и подпись осталась
        // единственным, что о настройке сказано: «kill switch» на её месте
        // ничего не сообщил бы тому, кто видит её впервые.
        for label in [
            crate::i18n::s().kill_switch,
            crate::i18n::s().allow_lan,
            crate::i18n::s().autostart,
            crate::i18n::s().autoconnect,
        ] {
            assert!(
                label.split_whitespace().count() > 2,
                "подпись `{label}` не объясняет настройку"
            );
        }
    }

    #[test]
    fn the_theme_is_not_offered_here() {
        // Её переключает кружок в шапке. Два пути до одной настройки — это
        // настройка, которая однажды разойдётся сама с собой.
        let state = State::default();
        let _ = view(&state);
    }

    #[test]
    fn nothing_here_waits_for_saving() {
        // Переключатели уезжают демону сразу, и «Сохранить» на этой вкладке
        // означала бы, что щелчок сам по себе ничего не сделал.
        let state = State {
            dirty: true,
            ..State::default()
        };
        let _ = view(&state);
    }

    #[test]
    fn every_switch_renders_in_both_positions() {
        // Строка рисуется двумя наборами цветов, и ни один из них не должен
        // ронять отрисовку.
        let mut state = State::default();
        for value in [true, false] {
            state.config.app.autostart = value;
            state.config.app.autoconnect = value;
            state.config.network.kill_switch = value;
            state.config.network.allow_lan = value;
            let _ = view(&state);
        }
    }
}
