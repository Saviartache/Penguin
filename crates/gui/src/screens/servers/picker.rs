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
//! # Почему строка, а не выпадающий список
//!
//! Выбирают здесь один раз и по незнанию: разница между `http` и `https`
//! человеку, который пришёл вставить настройки от провайдера, не очевидна.
//! Выпадающий список показывает только имена; строка с пояснением отвечает на
//! вопрос «а какой мой» до того, как его зададут.

use iced::widget::button;
use iced::{Alignment, Element, Length};
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

    let content = Flex::col()
        .push_auto(ui::faint(
            &state.palette,
            crate::i18n::s().choose_protocol_hint,
            type_scale::MICRO,
        ))
        .push_auto(ui::scroll_box(list, HEIGHT))
        .gap(gap::SM)
        .build();

    Modal::new(content)
        .title(crate::i18n::s().choose_protocol)
        .max_width(WIDTH)
        // Ряда ответов у окна нет: выбор и есть ответ, а кнопка «Дальше» под
        // списком, в котором щёлкают по строке, ничего не добавляет.
        .on_close(Message::Servers(ServersMessage::PickerClosed))
        .on_backdrop(Message::Servers(ServersMessage::PickerClosed))
        .build()
        .into()
}

/// Строка списка: имя протокола и чем он отличается от соседнего.
fn row<'a>(state: &'a State, spec: &'static ProtocolSpec) -> Element<'a, Message> {
    let strings = crate::i18n::s();

    let text = Flex::col()
        .w(Size::FILL)
        .push_auto(
            iced::widget::text(spec.label)
                .size(type_scale::LEAD)
                .color(state.palette.text),
        )
        .push_auto(ui::faint(
            &state.palette,
            (spec.summary)(strings),
            type_scale::MICRO,
        ))
        .gap(gap::NONE)
        .align(Alignment::Start)
        .build();

    button(text)
        .width(Length::Fill)
        .padding(gap::SM)
        .style(uikit::style::button::ghost)
        .on_press(Message::Servers(ServersMessage::ProtocolChosen(spec.id)))
        .into()
}

#[cfg(test)]
mod tests {
    use uikit::style::tokens::ink;

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
    fn every_row_says_what_it_is() {
        // Пустая строка под именем — это место, отведённое под ответ, в
        // котором ответа нет.
        for spec in protocol::ALL {
            assert!(
                !(spec.summary)(crate::i18n::s()).trim().is_empty(),
                "`{}` без пояснения",
                spec.id
            );
        }
    }

    #[test]
    fn the_list_fits_the_smallest_window() {
        // Растянутое содержимое в панели «по содержимому» схлопывается в ноль,
        // поэтому высота фиксированная — и обязана помещаться.
        const { assert!(HEIGHT < crate::app::EXPANDED.height) };
    }

    #[test]
    fn ink_levels_are_used() {
        // Подпись ярче пояснения: иначе строка читается как один абзац.
        let palette = State::default().palette;
        assert_ne!(palette.text.a, ink::level(&palette, ink::TERTIARY).a);
    }
}
