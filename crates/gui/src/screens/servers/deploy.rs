//! Окно развёртывания сервера Pingwin: поля SSH и сервера, потом ход работы.
//!
//! Пока идёт работа, полей нет: вместо них этапы, текущий отмечен, под ним его
//! последняя новость. `Esc` тогда не закрывает окно — оборвать можно только
//! «Отменой».

use iced::Element;
use iced::widget::text;
use uikit::layout::{Flex, gap};
use uikit::tokens::type_scale;
use uikit::widgets::{Modal, TextInput};

use crate::app::message::{DeployMessage, Message, ServersMessage};
use crate::app::state::State;
use crate::forms::deploy::progress::title;
use crate::forms::deploy::{Deploy, Field, Mark, Progress};
use crate::i18n::Strings;
use crate::ui;

/// Ширина окна — как у формы профиля.
const WIDTH: f32 = 620.0;

/// Высота прокручиваемой части, как у формы профиля.
const BODY_HEIGHT: f32 = 300.0;

/// Собирает окно развёртывания.
pub fn view<'a>(state: &'a State, deploy: &'a Deploy) -> Element<'a, Message> {
    let strings = crate::i18n::s();
    let cancel = message(DeployMessage::Cancelled);

    let modal = match &deploy.progress {
        Some(progress) => Modal::new(stages(state, progress)).action(strings.cancel, cancel),
        None => Modal::new(form(state, deploy))
            .action(strings.deploy, message(DeployMessage::Started))
            .action(strings.cancel, cancel.clone())
            .on_close(cancel.clone())
            .on_backdrop(cancel),
    };

    modal
        .title(format!("{} · Pingwin", strings.deploy_server))
        .max_width(WIDTH)
        .build()
        .into()
}

fn message(message: DeployMessage) -> Message {
    Message::Servers(ServersMessage::Deploy(message))
}

fn form<'a>(state: &'a State, deploy: &'a Deploy) -> Element<'a, Message> {
    let strings = crate::i18n::s();
    let mut rows = Flex::col();
    for field in Field::ALL {
        rows = rows.push_auto(row(strings, deploy, field));
        // Без указывающего имени сертификат не выпустится.
        if field == Field::Domain {
            rows = rows.push_auto(ui::muted(
                &state.palette,
                strings.deploy_domain_hint,
                type_scale::MICRO,
            ));
        }
    }

    Flex::col()
        .push_auto(ui::scroll_box(rows.gap(gap::MD).build(), BODY_HEIGHT))
        .push_auto(problem(state, deploy))
        .gap(gap::SM)
        .build()
}

fn row<'a>(strings: &'static Strings, deploy: &'a Deploy, field: Field) -> Element<'a, Message> {
    let (label, example) = labels(strings, field);
    ui::form_row(
        label,
        TextInput::new(example, deploy.form.get(field))
            .secure(field == Field::Password)
            .on_input(move |value| message(DeployMessage::Changed(field, value)))
            .build(),
    )
}

/// Подпись и подсказка внутри поля.
fn labels(strings: &'static Strings, field: Field) -> (&'static str, &'static str) {
    match field {
        Field::Host => (strings.server_address, "203.0.113.5"),
        Field::SshPort => (strings.ssh_port, "22"),
        Field::SshUser => (strings.ssh_user, "root"),
        Field::Password => (strings.ssh_password, strings.ssh_password_hint),
        Field::KeyFile => (strings.ssh_key_file, strings.optional_hint),
        Field::Domain => (strings.deploy_domain, "vpn.example.com"),
        Field::Port => (strings.deploy_port, strings.deploy_port_hint),
        Field::Email => (strings.deploy_email, strings.optional_hint),
        Field::User => (strings.deploy_user, "client"),
    }
}

/// Прошлая неудача важнее: поля могли быть верны, а сервер — нет.
fn problem<'a>(state: &'a State, deploy: &'a Deploy) -> Element<'a, Message> {
    let reason = deploy
        .error
        .clone()
        .or_else(|| deploy.form.request("").err());
    match reason {
        Some(reason) => ui::muted(&state.palette, reason, type_scale::MICRO),
        None => ui::spring(),
    }
}

fn stages<'a>(state: &'a State, progress: &'a Progress) -> Element<'a, Message> {
    let mut list = Flex::col();
    for (id, mark) in progress.stages() {
        let line = title(id);
        list = list.push_auto(match mark {
            Mark::Done => ui::muted(&state.palette, format!("✓ {line}"), type_scale::BODY),
            Mark::Current => text(format!("› {line}")).size(type_scale::BODY).into(),
            Mark::Pending => ui::faint(&state.palette, format!("· {line}"), type_scale::BODY),
        });
        if mark == Mark::Current && !progress.text.is_empty() {
            list = list.push_auto(ui::muted(
                &state.palette,
                format!("  {}", progress.text),
                type_scale::MICRO,
            ));
        }
    }
    ui::scroll_box(list.gap(gap::XS).build(), BODY_HEIGHT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::deploy::Event;

    #[test]
    fn renders_the_form() {
        let _ = view(&State::default(), &Deploy::default());
    }

    #[test]
    fn renders_a_failure() {
        let deploy = Deploy {
            error: Some("Сертификат: имя не указывает на сервер".to_owned()),
            ..Deploy::default()
        };
        let _ = view(&State::default(), &deploy);
    }

    #[test]
    fn renders_the_stages_with_unknown_ones() {
        let mut progress = Progress::default();
        progress.apply(Event::Step("build".to_owned()));
        progress.apply(Event::Text("Step 3/9".to_owned()));
        progress.apply(Event::Step("swap2".to_owned()));
        let deploy = Deploy {
            progress: Some(progress),
            ..Deploy::default()
        };
        let _ = view(&State::default(), &deploy);
    }

    #[test]
    fn the_deploy_dialog_replaces_the_editor() {
        let mut state = State::default();
        state.servers.editor = Some(crate::forms::server::Draft::default());
        state.servers.deploy = Some(Deploy::default());
        let _ = crate::screens::servers::view(&state);
    }

    #[test]
    fn the_body_fits_the_smallest_window() {
        const { assert!(BODY_HEIGHT < crate::app::EXPANDED.height) };
    }
}
