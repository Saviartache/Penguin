//! Выбор протокола — первый шаг «Добавить сервер».
//!
//! Поля формы и есть протокол, поэтому сначала вопрос «чем подключаться».
//! Протоколов много, выбирают глазами: разделы по транспорту, в каждом — сетка.
//! WireGuard ведёт не в форму, а в окно выбора способа ([`super::wireguard`]).

use iced::widget::button;
use iced::{Element, Length};
use uikit::layout::{Flex, Grid, Sizable, Size, gap};
use uikit::tokens::type_scale;
use uikit::widgets::Modal;

use crate::app::message::{Message, ServersMessage};
use crate::app::state::State;
use crate::forms::protocol::{self, Group, ProtocolSpec};
use crate::ui;

/// Ширина окна — как у формы, без прыжка размера.
const WIDTH: f32 = 620.0;

/// Высота прокручиваемой части: фиксированная, растянутое схлопнулось бы в ноль.
const HEIGHT: f32 = 380.0;

/// Колонок в разделе: самая длинная подпись ещё влезает.
const COLUMNS: usize = 3;

/// Собирает окно выбора протокола.
pub fn view(state: &State) -> Element<'_, Message> {
    let list = Flex::col()
        .w(Size::FILL)
        .extend(protocol::GROUPS.iter().map(|group| section(state, group)))
        .gap(gap::MD)
        .build();

    // Ряда ответов нет: выбор и есть ответ.
    Modal::new(ui::scroll_box(list, HEIGHT))
        .title(crate::i18n::s().choose_protocol)
        .max_width(WIDTH)
        .on_close(Message::Servers(ServersMessage::PickerClosed))
        .on_backdrop(Message::Servers(ServersMessage::PickerClosed))
        .build()
        .into()
}

fn section<'a>(state: &'a State, group: &'static Group) -> Element<'a, Message> {
    let grid = Grid::new(COLUMNS)
        .extend(group.protocols.iter().map(|spec| row(state, spec)))
        .gap(gap::XS);

    Flex::col()
        .w(Size::FILL)
        .push_auto(ui::faint(
            &state.palette,
            (group.title)(crate::i18n::s()),
            type_scale::MICRO,
        ))
        .push_auto(grid)
        .gap(gap::XS)
        .build()
}

fn row<'a>(state: &'a State, spec: &'static ProtocolSpec) -> Element<'a, Message> {
    let label = iced::widget::text(spec.label)
        .size(type_scale::LEAD)
        .color(state.palette.text)
        .width(Length::Fill);

    button(label)
        .width(Length::Fill)
        .padding(gap::SM)
        .style(uikit::button::ghost)
        .on_press(Message::Servers(ServersMessage::ProtocolChosen(spec.id)))
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_protocol_in_the_catalog() {
        let state = State::default();
        let _ = view(&state);
        assert!(protocol::ALL.len() >= 4);
    }

    #[test]
    fn every_row_is_named() {
        for spec in protocol::ALL {
            assert!(!spec.label.trim().is_empty(), "`{}` без подписи", spec.id);
        }
    }

    #[test]
    fn the_list_fits_the_smallest_window() {
        const { assert!(HEIGHT < crate::app::EXPANDED.height) };
    }
}
