//! Строка выбора: пункт списка, раскрытого прямо в консоли.

use iced::mouse::ScrollDelta;
use iced::theme::Palette;
use iced::widget::{button, mouse_area};
use iced::{Background, Element, Length, Theme};
use uikit::color::is_dark;
use uikit::layout::{Flex, Sizable, Size};
use uikit::tokens::{ink, state, surface};

use super::{CELL, DOTS, LIMIT, LINE, Picker, SPACING, cell, clip, filler};

/// Метка выбранного пункта.
const MARK: char = '>';

/// Пункт: метка и имя слева, примечание у правого края; без `picker` не нажимается.
pub(super) fn row<'a, Message: Clone + 'a>(
    palette: &Palette,
    name: &str,
    note: &str,
    chosen: bool,
    index: usize,
    picker: Option<&Picker<Message>>,
) -> Element<'a, Message> {
    let (marker, tone) = if chosen {
        (MARK, palette.text)
    } else {
        (' ', ink::level(palette, ink::SECONDARY))
    };

    let line = Flex::row()
        .w(Size::FILL)
        .push_auto(cell(format!("{marker} {}", clip(name, LIMIT)), tone))
        .push(filler(palette, &DOTS, true))
        .push_auto(cell(note.to_owned(), tone))
        .gap(CELL)
        .build();

    let Some(picker) = picker else {
        return line;
    };
    let scroll = picker.scroll;
    let pressable = button(line)
        .padding(0)
        .width(Length::Fill)
        .style(style)
        .on_press((picker.choose)(index));

    mouse_area(pressable)
        .on_scroll(move |delta| scroll(rows(delta)))
        .into()
}

/// Колесо в строках списка: вниз — плюс.
fn rows(delta: ScrollDelta) -> f32 {
    match delta {
        ScrollDelta::Lines { y, .. } => -y,
        ScrollDelta::Pixels { y, .. } => -y / (LINE + SPACING),
    }
}

/// Под курсором — полоса, как курсор выбора в текстовом интерфейсе.
fn style(theme: &Theme, status: button::Status) -> button::Style {
    let background = match status {
        button::Status::Hovered | button::Status::Pressed => Some(Background::Color(
            surface::film(is_dark(theme.palette().background), state::STEP),
        )),
        button::Status::Active | button::Status::Disabled => None,
    };
    button::Style {
        background,
        ..button::Style::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wheel_down_moves_the_list_down() {
        assert_eq!(rows(ScrollDelta::Lines { x: 0.0, y: -1.0 }), 1.0);
    }

    #[test]
    fn a_trackpad_scrolls_by_fractions_of_a_row() {
        let step = rows(ScrollDelta::Pixels {
            x: 0.0,
            y: -(LINE + SPACING) / 2.0,
        });
        assert_eq!(step, 0.5);
    }
}
