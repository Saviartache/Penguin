//! Модальное окно профиля: ссылка, имя и поля выбранного протокола.
//!
//! Поля приносит описание протокола ([`crate::forms::protocol`]). Поле ссылки
//! есть только у протоколов со ссылками. Подсказки стоят внутри поля, не под ним.

use iced::Element;
use uikit::layout::{Flex, gap};
use uikit::tokens::type_scale;
use uikit::widgets::{Checkbox, Modal, Select, TextInput};

use crate::app::message::{DeployMessage, Message, ServersMessage};
use crate::app::state::State;
use crate::forms::protocol::FieldSpec;
use crate::forms::server::Draft;
use crate::ui;

/// Ширина окна: подпись и поле в одной строке.
const WIDTH: f32 = 620.0;

/// Высота прокручиваемой части: фиксированная (растянутое схлопнулось бы в
/// ноль), помещается в наименьшее окно.
const FORM_HEIGHT: f32 = 300.0;

/// Собирает модальное окно правки профиля.
pub fn view<'a>(state: &'a State, draft: &'a Draft) -> Element<'a, Message> {
    // Строки добавляются по одной: пустышка в столбце с зазором — видимая дыра.
    let mut form = Flex::col();
    if draft.spec().is_some_and(|spec| spec.takes_links()) {
        form = form.push_auto(link(state));
    }
    form = form.push_auto(name(draft));
    if draft.spec().is_none() {
        form = form.push_auto(unknown(state));
    }

    let form = form
        .extend(
            draft
                .fields()
                .iter()
                .enumerate()
                .map(|(index, field)| row(draft, index, field)),
        )
        .gap(gap::MD)
        .build();

    let content = Flex::col()
        .push_auto(ui::scroll_box(form, FORM_HEIGHT))
        .push_auto(problem(state, draft))
        .gap(gap::SM)
        .build();

    // `Esc` и нажатие мимо панели — «Отмена».
    let mut modal = Modal::new(content)
        .title(title(draft))
        .max_width(WIDTH)
        .action(
            crate::i18n::s().save,
            Message::Servers(ServersMessage::EditorSubmitted),
        )
        .on_close(Message::Servers(ServersMessage::EditorClosed))
        .on_backdrop(Message::Servers(ServersMessage::EditorClosed));

    if crate::app::update::deploy::offers_deploy(draft) {
        modal = modal.action(
            crate::i18n::s().deploy_server,
            Message::Servers(ServersMessage::Deploy(DeployMessage::Opened)),
        );
    }

    // Удаление — у существующего профиля и последним в ряду.
    if let Some(id) = &draft.id {
        modal = modal.action(
            crate::i18n::s().remove,
            Message::Servers(ServersMessage::Removed(id.clone())),
        );
    }

    modal.build().into()
}

/// Заголовок: что делаем и с каким протоколом (в форме он выглядел бы полем).
fn title(draft: &Draft) -> String {
    let what = if draft.is_edit() {
        crate::i18n::s().edit_server
    } else {
        crate::i18n::s().new_server
    };

    match draft.spec() {
        Some(spec) => format!("{what} · {}", spec.label),
        None => format!("{what} · {}", draft.protocol()),
    }
}

fn link(state: &State) -> Element<'_, Message> {
    ui::form_row(
        crate::i18n::s().link,
        TextInput::new(crate::i18n::s().link_example, &state.servers.link)
            .on_input(|value| Message::Servers(ServersMessage::LinkChanged(value)))
            .build(),
    )
}

/// Имя профиля — единственное поле, общее всем протоколам.
fn name(draft: &Draft) -> Element<'_, Message> {
    ui::form_row(
        crate::i18n::s().server_name,
        TextInput::new("", &draft.name)
            .on_input(|value| Message::Servers(ServersMessage::EditorNameChanged(value)))
            .build(),
    )
}

/// Объяснение для неизвестного протокола: настройки не потеряются.
fn unknown(state: &State) -> Element<'_, Message> {
    ui::muted(
        &state.palette,
        crate::i18n::s().protocol_unknown,
        type_scale::MICRO,
    )
}

fn row<'a>(draft: &'a Draft, index: usize, field: &'static FieldSpec) -> Element<'a, Message> {
    let strings = crate::i18n::s();
    let label = (field.label)(strings);

    if field.is_flag() {
        return ui::form_row(
            label,
            Checkbox::new(String::new(), draft.flag(field.key)).on_toggle(move |value| {
                Message::Servers(ServersMessage::EditorToggled(index, value))
            }),
        );
    }

    if field.is_choice() {
        return ui::form_row(label, choice(draft, index, field));
    }

    let example = field.example.map_or("", |example| example(strings));

    ui::form_row(
        label,
        TextInput::new(example, draft.text(field.key))
            .secure(field.is_secret())
            .on_input(move |value| Message::Servers(ServersMessage::EditorChanged(index, value)))
            .build(),
    )
}

/// Список выбора; значение вне набора дописывается: сервер может уметь больше
/// нашего, и пустота потеряла бы его при сохранении.
fn choice<'a>(draft: &'a Draft, index: usize, field: &'static FieldSpec) -> Element<'a, Message> {
    let current = draft.text(field.key);
    let mut options: Vec<String> = field.options.iter().map(|o| (*o).to_owned()).collect();
    if !current.is_empty() && !options.iter().any(|option| option == current) {
        options.push(current.to_owned());
    }

    Select::new(options, Some(current.to_owned()), move |value| {
        Message::Servers(ServersMessage::EditorChanged(index, value))
    })
    .view()
}

/// Причина, по которой профиль пока не собирается; видна сразу, не по нажатию.
fn problem<'a>(state: &'a State, draft: &'a Draft) -> Element<'a, Message> {
    // Неразобравшаяся ссылка важнее: остальные поля заполнены не тем.
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
    use penguin_config::schema::outbound::RawOutbound;
    use penguin_config::schema::profile::Profile;
    use serde_json::json;

    use super::*;
    use crate::forms::protocol;

    fn filled() -> Draft {
        let mut draft = Draft::default();
        draft.name = "Дом".to_owned();
        draft.set_text("server", "example.com:443".to_owned());
        draft.set_text("password", "секрет".to_owned());
        draft
    }

    #[test]
    fn renders_a_new_profile() {
        let _ = view(&State::default(), &Draft::default());
    }

    #[test]
    fn renders_every_protocol_in_the_catalog() {
        let state = State::default();
        for spec in protocol::ALL {
            let _ = view(&state, &Draft::new(spec));
        }
    }

    #[test]
    fn renders_an_edited_profile() {
        let _ = view(
            &State::default(),
            &filled().with_id(Some("home".to_owned())),
        );
    }

    #[test]
    fn the_title_names_the_protocol() {
        let new = title(&Draft::new(protocol::by_id("socks5").expect("есть")));
        assert!(new.contains("SOCKS5"), "нет протокола: {new}");
        assert!(new.contains(crate::i18n::s().new_server));

        let edit = title(&filled().with_id(Some("home".to_owned())));
        assert!(edit.contains(crate::i18n::s().edit_server));
    }

    #[test]
    fn a_protocol_without_links_has_no_link_field() {
        for spec in protocol::ALL {
            let draft = Draft::new(spec);
            assert_eq!(
                draft.spec().is_some_and(|spec| spec.takes_links()),
                spec.takes_links(),
                "`{}`: форма и описание разошлись",
                spec.id
            );
            let _ = view(&State::default(), &draft);
        }

        let with_links = protocol::by_id("socks5").expect("есть");
        assert!(with_links.takes_links());
        let without = protocol::by_id("socks5-tls").expect("есть");
        assert!(
            !without.takes_links(),
            "у `socks5-tls` завелась схема ссылок — тогда нужен и разбор"
        );
    }

    #[test]
    fn a_problem_is_shown_before_saving() {
        assert!(Draft::default().to_profile().is_err());
        let _ = view(&State::default(), &Draft::default());
    }

    #[test]
    fn a_broken_link_is_reported_instead_of_the_form() {
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
    fn an_unknown_protocol_renders_with_an_explanation() {
        let profile = Profile::new(
            "чужой",
            "Чужой",
            RawOutbound::new("телепатия", json!({ "server": "example.com:443" })),
        );
        let draft = Draft::from_profile(&profile);
        assert!(draft.fields().is_empty());
        let _ = view(&State::default(), &draft);
    }

    #[test]
    fn the_form_fits_the_smallest_window() {
        const { assert!(FORM_HEIGHT < crate::app::EXPANDED.height) };
    }
}
