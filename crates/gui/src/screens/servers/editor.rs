//! Модальное окно профиля: ссылка, адрес, пароль, полоса, TLS.
//!
//! Первое поле — ссылка-приглашение. Её присылают в мессенджере, и переносить
//! из неё поля руками — семь шансов ошибиться в пароле; вставил — остальное
//! заполнилось само. Всё, что ниже, остаётся на месте для тех, у кого ссылки
//! нет: настройки от провайдера приходят и списком полей.
//!
//! Подсказок под полями нет намеренно. В модальном окне их некуда деть: они
//! удваивают его высоту, а прочитывают их один раз в жизни. То, что нужно
//! знать про формат, стоит подсказкой **внутри** поля и исчезает, как только
//! человек начал печатать.

use iced::Element;
use uikit::layout::{Flex, gap};
use uikit::style::tokens::type_scale;
use uikit::widgets::{Checkbox, Modal, TextInput};

use crate::app::message::{Message, ServersMessage};
use crate::app::state::State;
use crate::forms::server::{Draft, Field};
use crate::ui;

/// Ширина окна.
///
/// Шире умолчания кита: там окно рассчитано на сообщение в две строки, а здесь
/// в нём форма, у которой подпись и поле стоят в одной строке.
const WIDTH: f32 = 620.0;

/// Высота прокручиваемой части формы.
///
/// Фиксированная, а не «сколько поместится»: растянутое содержимое в панели
/// «по содержимому» схлопывается в ноль, а ноль роняет отрисовку. Значение
/// подобрано так, чтобы окно целиком помещалось в наименьшее окно программы.
const FORM_HEIGHT: f32 = 300.0;

/// Собирает модальное окно правки профиля.
pub fn view<'a>(state: &'a State, draft: &'a Draft) -> Element<'a, Message> {
    let title = if draft.is_edit() {
        crate::i18n::s().edit_server
    } else {
        crate::i18n::s().new_server
    };

    let form = Flex::col()
        .push_auto(link(state))
        .push_auto(field(
            crate::i18n::s().server_name,
            draft,
            Field::Name,
            "",
            false,
        ))
        .push_auto(field(
            crate::i18n::s().server_address,
            draft,
            Field::Server,
            crate::i18n::s().server_address_example,
            false,
        ))
        .push_auto(field(
            crate::i18n::s().password,
            draft,
            Field::Password,
            "",
            true,
        ))
        .push_auto(field(
            crate::i18n::s().bandwidth_down,
            draft,
            Field::Down,
            crate::i18n::s().bandwidth_down_example,
            false,
        ))
        .push_auto(field(
            crate::i18n::s().bandwidth_up,
            draft,
            Field::Up,
            crate::i18n::s().bandwidth_up_example,
            false,
        ))
        .push_auto(field(
            crate::i18n::s().sni,
            draft,
            Field::Sni,
            crate::i18n::s().sni_example,
            false,
        ))
        .push_auto(field(
            crate::i18n::s().obfs,
            draft,
            Field::Obfs,
            crate::i18n::s().obfs_example,
            true,
        ))
        .push_auto(ui::form_row(
            crate::i18n::s().insecure,
            Checkbox::new(String::new(), draft.insecure)
                .on_toggle(|value| Message::Servers(ServersMessage::EditorInsecureToggled(value))),
        ))
        .gap(gap::MD)
        .build();

    let content = Flex::col()
        .push_auto(ui::scroll_box(form, FORM_HEIGHT))
        .push_auto(problem(state, draft))
        .gap(gap::SM)
        .build();

    let mut modal = Modal::new(content)
        .title(title)
        .max_width(WIDTH)
        // `Esc` и нажатие мимо панели означают «Отмена»: отдельной кнопки для
        // этого не нужно, а место в ряду ответов дорого.
        .action(
            crate::i18n::s().save,
            Message::Servers(ServersMessage::EditorSubmitted),
        )
        .on_close(Message::Servers(ServersMessage::EditorClosed))
        .on_backdrop(Message::Servers(ServersMessage::EditorClosed));

    // Удаление — только у существующего профиля и последним в ряду: первый
    // ответ набран тоном окна и означает «то, зачем сюда пришли».
    if let Some(id) = &draft.id {
        modal = modal.action(
            crate::i18n::s().remove,
            Message::Servers(ServersMessage::Removed(id.clone())),
        );
    }

    modal.build().into()
}

/// Поле вставки ссылки-приглашения.
fn link(state: &State) -> Element<'_, Message> {
    ui::form_row(
        crate::i18n::s().link,
        TextInput::new(crate::i18n::s().link_example, &state.servers.link)
            .on_input(|value| Message::Servers(ServersMessage::LinkChanged(value)))
            .build(),
    )
}

/// Одно поле формы.
fn field<'a>(
    label: &'a str,
    draft: &'a Draft,
    which: Field,
    example: &'a str,
    secret: bool,
) -> Element<'a, Message> {
    ui::form_row(
        label,
        TextInput::new(example, draft.get(which))
            .secure(secret)
            .on_input(move |value| Message::Servers(ServersMessage::EditorChanged(which, value)))
            .build(),
    )
}

/// Причина, по которой профиль пока не собирается.
///
/// Показывается сразу, а не по нажатию: иначе человек заполняет форму до конца
/// и только потом узнаёт, что адрес не разобрался.
fn problem<'a>(state: &'a State, draft: &'a Draft) -> Element<'a, Message> {
    // Неразобравшаяся ссылка важнее: пока она лежит в поле, остальные поля
    // заполнены не тем, чем человек думает.
    let reason = if crate::forms::link::looks_like_link(&state.servers.link) {
        crate::forms::link::parse(&state.servers.link)
            .err()
            .or_else(|| draft.to_profile().err())
    } else {
        draft.to_profile().err()
    };

    match reason {
        Some(reason) => ui::muted(&state.palette, reason, type_scale::MICRO),
        None => ui::spring(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled() -> Draft {
        Draft {
            name: "Дом".to_owned(),
            server: "example.com:443".to_owned(),
            password: "секрет".to_owned(),
            ..Draft::default()
        }
    }

    #[test]
    fn renders_a_new_profile() {
        // Пустая форма — состояние, с которого начинается любой первый запуск.
        let _ = view(&State::default(), &Draft::default());
    }

    #[test]
    fn renders_an_edited_profile() {
        let draft = Draft {
            id: Some("home".to_owned()),
            ..filled()
        };
        let _ = view(&State::default(), &draft);
    }

    #[test]
    fn a_problem_is_shown_before_saving() {
        // Пустая форма не собирается — и причина обязана быть видна сразу.
        assert!(Draft::default().to_profile().is_err());
        let _ = view(&State::default(), &Draft::default());
    }

    #[test]
    fn a_broken_link_is_reported_instead_of_the_form() {
        // Пока в поле лежит неразобравшаяся ссылка, остальные поля заполнены
        // не тем, чем человек думает.
        let mut state = State::default();
        state.servers.link = "hy2://без-пароля.example.com".to_owned();
        let _ = view(&state, &filled());
    }

    #[test]
    fn a_pasted_link_renders() {
        let mut state = State::default();
        state.servers.link =
            "hy2://source:s3cret@example.net:3478?sni=example.net#source".to_owned();
        let draft = crate::forms::link::parse(&state.servers.link).expect("ссылка разбирается");
        let _ = view(&state, &draft);
    }

    #[test]
    fn the_form_fits_the_smallest_window() {
        // Растянутое содержимое в панели «по содержимому» схлопывается в ноль,
        // поэтому высота фиксированная — и обязана помещаться.
        const { assert!(FORM_HEIGHT < crate::app::EXPANDED.height) };
    }
}
