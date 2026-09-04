//! Выбор протокола — первый шаг «Добавить сервер».
//!
//! # Почему это отдельный шаг, а не поле в форме
//!
//! Поля формы **и есть** протокол: у Hysteria 2 это полоса и обфускация, у
//! SOCKS5 — имя с паролем и переключатель UDP. Список протоколов внутри такой
//! формы означал бы, что половина полей на экране относится не к тому, что
//! выбрано, — и меняется прямо под руками, пока человек их заполняет.
//!
//! Поэтому сначала вопрос «чем подключаться», и только потом форма. Правки
//! существующего профиля это не касается: протокол у него уже выбран, и
//! менять его сменой полей нельзя — это другой сервер, а не тот же самый.
//!
//! # Почему список строк, а не выпадающий
//!
//! Протоколов будет много, и выбирают из них глазами: открытый список читается
//! целиком, а выпадающий приходится сперва открыть, чтобы узнать, что в нём.
//! Пояснений под именами нет — человек приходит сюда, уже зная, что ему
//! прислал провайдер, и лишняя строка под каждым именем растягивает список
//! ровно вдвое.

use iced::widget::button;
use iced::{Element, Length};
use uikit::layout::{Flex, Sizable, Size, gap};
use uikit::style::tokens::type_scale;
use uikit::widgets::Modal;

use crate::app::message::{Message, ServersMessage};
use crate::app::state::State;
use crate::forms::protocol::{self, ProtocolSpec};
use crate::ui;

/// Ширина окна — та же, что у формы: одно за другим, без прыжка размера.
const WIDTH: f32 = 620.0;

/// Высота прокручиваемой части.
///
/// Фиксированная, а не «сколько поместится»: растянутое содержимое в панели
/// «по содержимому» схлопывается в ноль, а ноль роняет отрисовку.
const HEIGHT: f32 = 300.0;

/// Собирает окно выбора протокола.
pub fn view(state: &State) -> Element<'_, Message> {
    let list = Flex::col()
        .w(Size::FILL)
        .extend(protocol::ALL.iter().map(|spec| row(state, spec)))
        .gap(gap::SM)
        .build();

    Modal::new(ui::scroll_box(list, HEIGHT))
        .title(crate::i18n::s().choose_protocol)
        .max_width(WIDTH)
        // Ряда ответов у окна нет: выбор и есть ответ, а кнопка «Дальше» под
        // списком, в котором щёлкают по строке, ничего не добавляет.
        .on_close(Message::Servers(ServersMessage::PickerClosed))
        .on_backdrop(Message::Servers(ServersMessage::PickerClosed))
        .build()
        .into()
}

/// Строка списка — имя протокола.
fn row<'a>(state: &'a State, spec: &'static ProtocolSpec) -> Element<'a, Message> {
    let label = iced::widget::text(spec.label)
        .size(type_scale::LEAD)
        .color(state.palette.text)
        .width(Length::Fill);

    button(label)
        .width(Length::Fill)
        .padding(gap::SM)
        .style(uikit::style::button::ghost)
        .on_press(Message::Servers(ServersMessage::ProtocolChosen(spec.id)))
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_protocol_in_the_catalog() {
        // Протокол, которого нет в списке, недостижим: другого пути к его
        // форме у человека нет.
        let state = State::default();
        let _ = view(&state);
        assert!(protocol::ALL.len() >= 4);
    }

    #[test]
    fn every_row_is_named() {
        // Строка без подписи — это строка, по которой не понять, куда она
        // ведёт.
        for spec in protocol::ALL {
            assert!(!spec.label.trim().is_empty(), "`{}` без подписи", spec.id);
        }
    }

    #[test]
    fn the_list_fits_the_smallest_window() {
        // Растянутое содержимое в панели «по содержимому» схлопывается в ноль,
        // поэтому высота фиксированная — и обязана помещаться.
        const { assert!(HEIGHT < crate::app::EXPANDED.height) };
    }
}
