//! Выбор протокола — первый шаг «Добавить сервер».
//!
//! Поля формы и есть протокол, поэтому сначала вопрос «чем подключаться». Список
//! открытый, без пояснений: протоколов много, выбирают глазами. WireGuard ведёт
//! не в форму, а в окно выбора способа ([`super::wireguard`]).

use iced::widget::button;
use iced::{Element, Length};
use uikit::layout::{Flex, Sizable, Size, gap};
use uikit::tokens::type_scale;
use uikit::widgets::Modal;

use crate::app::message::{Message, ServersMessage};
use crate::app::state::State;
use crate::forms::protocol::{self, ProtocolSpec};
use crate::ui;

/// Ширина окна — как у формы, без прыжка размера.
const WIDTH: f32 = 620.0;

/// Высота прокручиваемой части: фиксированная, растянутое схлопнулось бы в ноль.
const HEIGHT: f32 = 300.0;

/// Собирает окно выбора протокола.
pub fn view(state: &State) -> Element<'_, Message> {
    let list = Flex::col()
        .w(Size::FILL)
        .extend(protocol::ALL.iter().map(|spec| row(state, spec)))
        .gap(gap::SM)
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
