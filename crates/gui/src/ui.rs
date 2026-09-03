//! Мелочи, общие всем экранам: строка формы, пустое состояние, кнопка ряда.
//!
//! Не набор помощников для красоты. Здесь собрано то, что в `iced` разъезжается
//! само собой, если каждый экран решает это заново.
//!
//! Страницы с карточками-разделами здесь больше нет. Все четыре вкладки — это
//! панель терминала во всю высоту ([`crate::screens::table`]), и то, что
//! осталось в этом модуле, служит уже не им, а модальным окнам: у формы внутри
//! окна те же строки и те же два уровня приглушённого текста.
//!
//! # Размер задаётся явно и до конца
//!
//! Растянутый ребёнок внутри группы «по содержимому» **схлопывается в ноль**;
//! ноль означает квад нулевого размера, а его рендерер не принимает. Отсюда
//! правило: растягивается ровно один элемент на каждом уровне.
//!
//! # Прокрутка по правилам кита
//!
//! `iced` рисует полосу прокрутки **поверх** содержимого, поэтому отступы
//! задаёт содержимое, а не контейнер вокруг (правило 4.6 кита). Соблюдать это
//! в каждом экране отдельно — значит однажды не соблюсти.
//!
//! Палитра приходит параметром, потому что в `iced` цвет текста задаётся
//! конкретным значением, а `view` темы не получает.

use iced::theme::Palette;
use iced::widget::{Space, container, scrollable, text};
use iced::{Alignment, Element, Length};
use uikit::layout::{Flex, gap, grow};
use uikit::style::scrollbar;
use uikit::style::tokens::{ink, type_scale};
use uikit::widgets::{Button, ButtonVariant};

/// Шрифт всего окна.
///
/// Одно место на весь интерфейс. Он ставится умолчанием билдеру `iced` (см.
/// [`crate::run`]) и оттуда достаётся каждому виджету сам; ни один экран шрифт
/// больше не называет. Названный по второму разу, он однажды разойдётся с
/// остальным окном — а встроен в кит он ровно затем, чтобы на всех машинах окно
/// выглядело одинаково, без оглядки на то, какие шрифты стоят в системе.
pub const FONT: iced::Font = uikit::font::MONO;

/// сузить поле вдвое ради пустоты.
pub fn form_row<'a, Message: 'a>(
    label: &'a str,
    control: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    Flex::row()
        .push_sized(text(label).size(type_scale::LEAD), grow(2))
        .push_sized(control, grow(3))
        .gap(gap::LG)
        .align(Alignment::Center)
        .build()
}

/// Пустое состояние: почему здесь ничего нет.
///
/// Отдельным элементом, потому что пустой экран без объяснения читается как
/// «не загрузилось», и человек ждёт. Причина всегда одна из двух — «ещё не
/// пришло» или «нечего показывать», — и они требуют разных действий.
pub fn empty<'a, Message: 'a>(palette: &Palette, reason: &'a str) -> Element<'a, Message> {
    container(muted(palette, reason, type_scale::BODY))
        .width(Length::Fill)
        .padding(gap::SM)
        .into()
}

/// Приглушённый текст — второй уровень иерархии.
pub fn muted<'a, Message: 'a>(
    palette: &Palette,
    value: impl ToString,
    size: f32,
) -> Element<'a, Message> {
    text(value.to_string())
        .size(size)
        .color(ink::level(palette, ink::SECONDARY))
        .into()
}

/// Ещё тише: подсказка, счётчик, прочерк на месте пустого значения.
pub fn faint<'a, Message: 'a>(
    palette: &Palette,
    value: impl ToString,
    size: f32,
) -> Element<'a, Message> {
    text(value.to_string())
        .size(size)
        .color(ink::level(palette, ink::TERTIARY))
        .into()
}

/// Кнопка для ряда: подпись по содержимому, а не во всю ширину.
///
/// У кита подпись кнопки по умолчанию растянута на всю ширину — так у кнопок в
/// **столбце** совпадают размеры. В ряду это означает другое: кнопка забирает
/// всё свободное место, сосед схлопывается в ноль и пропадает с экрана
/// (`Button::hug` в ките описывает ровно этот случай).
///
/// В окне кнопки почти всегда стоят в ряду, поэтому здесь `hug` — умолчание, а
/// не исключение, о котором надо помнить в каждом месте.
pub fn button<'a, Message: Clone + 'a>(
    variant: ButtonVariant,
    label: &'a str,
) -> Button<'a, Message> {
    let button = match variant {
        ButtonVariant::Primary => Button::primary(label),
        ButtonVariant::Secondary => Button::secondary(label),
        ButtonVariant::Positive => Button::positive(label),
        ButtonVariant::Danger => Button::danger(label),
        ButtonVariant::Neutral => Button::neutral(label),
    };
    button.hug()
}

/// Распорка, отжимающая соседей к краям ряда.
pub fn spring<'a, Message: 'a>() -> Element<'a, Message> {
    Space::new().width(Length::Fill).into()
}

/// Прокручиваемый список внутри раздела.
///
/// Своя высота обязательна: список запущенных приложений — это полторы сотни
/// строк, и без ограничения он выдавливает с экрана всё остальное.
pub fn scroll_box<'a, Message: 'a>(
    content: impl Into<Element<'a, Message>>,
    height: f32,
) -> Element<'a, Message> {
    scrollable(
        container(content)
            .padding(scrollbar::safe(0.0))
            .width(Length::Fill),
    )
    .direction(scrollbar::vertical())
    .style(scrollbar::style())
    .width(Length::Fill)
    .height(Length::Fixed(height))
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    type Message = ();

    fn palette() -> Palette {
        uikit::ThemeType::Dark.to_iced_theme().palette()
    }

    #[test]
    fn a_scroll_box_keeps_the_height_it_was_given() {
        let list: Element<'_, Message> = scroll_box(text("строка"), 180.0);
        assert_eq!(list.as_widget().size().height, Length::Fixed(180.0));
    }

    #[test]
    fn the_two_muted_levels_differ() {
        // Иначе иерархии нет: подпись и подсказка читаются как один уровень.
        let palette = palette();
        assert_ne!(
            ink::level(&palette, ink::SECONDARY).a,
            ink::level(&palette, ink::TERTIARY).a
        );
    }

    #[test]
    fn everything_composes() {
        // То, из чего собрана форма модального окна: строка, пустое состояние
        // и список с прокруткой в одном столбце.
        let palette = palette();
        let _: Element<'_, Message> = Flex::col()
            .push_auto(form_row("Поле", text("значение")))
            .push_auto(empty(&palette, "пусто"))
            .push_auto(scroll_box(text("список"), 120.0))
            .push_auto(spring())
            .gap(gap::SM)
            .build();
    }
}
