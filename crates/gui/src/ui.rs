//! Мелочи, общие экранам и модальным окнам: строка формы, пустое состояние,
//! кнопка ряда, прокручиваемый список.
//!
//! Размер задаётся явно: растянутый ребёнок в группе «по содержимому»
//! схлопывается в ноль. Полоса прокрутки рисуется поверх содержимого, поэтому
//! отступы задаёт содержимое (правило 4.6 кита). Палитра приходит параметром:
//! `view` темы не получает.

use iced::theme::Palette;
use iced::widget::{Space, container, scrollable, text};
use iced::{Alignment, Element, Length};
use uikit::layout::{Flex, gap, grow};
use uikit::scrollbar;
use uikit::tokens::{ink, type_scale};
use uikit::widgets::{Button, ButtonVariant};

/// Шрифт всего окна: единственное место, где он назван (умолчание билдера `iced`).
pub const FONT: iced::Font = uikit::font::MONO;

/// Строка формы: подпись слева, поле справа (2:3).
pub fn form_row<'a, Message: 'a>(
    label: &'a str,
    control: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    // Ячейка ростом с поле ввода: флажок ниже поля, и без неё шаг строк
    // формы у него короче — он прилипает к полю над собой.
    let control = container(control)
        .width(Length::Fill)
        .center_y(Length::Fixed(uikit::control::CONTROL_HEIGHT));
    Flex::row()
        .push_sized(text(label).size(type_scale::LEAD), grow(2))
        .push_sized(control, grow(3))
        .gap(gap::LG)
        .align(Alignment::Center)
        .build()
}

/// Пустое состояние: пустой экран без объяснения читается как «не загрузилось».
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

/// Ещё тише: подсказка, счётчик, прочерк.
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

/// Кнопка для ряда: `hug`, иначе растянутая забирает место и сосед схлопывается.
pub fn button<'a, Message: Clone + 'a>(
    variant: ButtonVariant,
    label: &'a str,
) -> Button<'a, Message> {
    let button = match variant {
        ButtonVariant::Primary => Button::primary(label),
        ButtonVariant::Secondary => Button::secondary(label),
        ButtonVariant::Positive => Button::positive(label),
        ButtonVariant::Danger => Button::danger(label),
        ButtonVariant::Caution => Button::caution(label),
        ButtonVariant::Neutral => Button::neutral(label),
    };
    button.hug()
}

/// Распорка, отжимающая соседей к краям ряда.
pub fn spring<'a, Message: 'a>() -> Element<'a, Message> {
    Space::new().width(Length::Fill).into()
}

/// Прокручиваемый список заданной высоты: без неё сто строк выдавят остальное.
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
        let palette = palette();
        assert_ne!(
            ink::level(&palette, ink::SECONDARY).a,
            ink::level(&palette, ink::TERTIARY).a
        );
    }

    #[test]
    fn everything_composes() {
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
