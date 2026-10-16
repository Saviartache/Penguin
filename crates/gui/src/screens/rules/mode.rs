//! Последняя строка списка: куда идёт всё, что не подошло ни под одну группу.
//!
//! Стоит под группами, а не над ними: проверяется последней, и порядок на экране
//! совпадает с порядком проверки.

use iced::{Alignment, Element};
use penguin_config::schema::routing::TunnelMode;
use uikit::layout::{Flex, Sizable, gap, px};
use uikit::tokens::ink;
use uikit::widgets::ButtonVariant;

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::screens::table::{BUTTON_HEIGHT, ROW_PADDING, glyphs};
use crate::ui;

/// Собирает строку «Всё остальное» с выбором из трёх.
pub fn view(state: &State) -> Element<'_, Message> {
    let palette = &state.palette;
    let strings = crate::i18n::s();
    let current = state.config.routing.mode;

    let mut row = Flex::row()
        .push_auto(glyphs(strings.rest, palette.text))
        .push_auto(glyphs(
            strings.rest_hint,
            ink::level(palette, ink::TERTIARY),
        ))
        .push(ui::spring());

    for mode in TunnelMode::ALL {
        let variant = if mode == current {
            ButtonVariant::Primary
        } else {
            ButtonVariant::Secondary
        };
        row = row.push_auto(
            ui::button(variant, crate::i18n::mode_label(mode))
                .h(px(BUTTON_HEIGHT))
                .on_press(Message::SplitTunnel(SplitTunnelMessage::ModeSelected(mode))),
        );
    }

    iced::widget::container(row.gap(gap::SM).align(Alignment::Center).build())
        .padding(ROW_PADDING)
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_in_every_mode() {
        let mut state = State::default();
        for mode in TunnelMode::ALL {
            state.config.routing.mode = mode;
            let _ = view(&state);
        }
    }
}
