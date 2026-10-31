//! Развёртывание сервера Pingwin из редактора нового профиля.

use iced::Task;

use crate::app::App;
use crate::app::message::{DeployMessage, Message};
use crate::forms::deploy::Deploy;

/// Разбирает окно развёртывания.
pub fn handle(app: &mut App, message: DeployMessage) -> Task<Message> {
    match message {
        DeployMessage::Opened => {
            let servers = &mut app.state_mut().servers;
            if servers.editor.as_ref().is_some_and(offers_deploy) {
                servers.deploy = Some(Deploy::default());
            }
            Task::none()
        }
        DeployMessage::Changed(field, value) => {
            if let Some(deploy) = app.state_mut().servers.deploy.as_mut()
                && !deploy.running()
            {
                deploy.form.set(field, value);
            }
            Task::none()
        }
        DeployMessage::Started => start(app),
        DeployMessage::Event(event) => {
            if let Some(deploy) = app.state_mut().servers.deploy.as_mut() {
                deploy.apply(event);
            }
            Task::none()
        }
        DeployMessage::Finished(result) => {
            finished(app, result);
            Task::none()
        }
        DeployMessage::Cancelled => {
            cancel(app);
            Task::none()
        }
    }
}

/// Развернуть можно только новый профиль Pingwin: правка уже знает свой сервер.
pub fn offers_deploy(draft: &crate::forms::server::Draft) -> bool {
    draft.protocol() == "pingwin" && !draft.is_edit()
}

/// Запускает CLI; неверная форма не запускается — причина видна в окне.
fn start(app: &mut App) -> Task<Message> {
    let servers = &mut app.state_mut().servers;
    let profile = servers
        .editor
        .as_ref()
        .map_or_else(String::new, |draft| draft.name.clone());
    let Some(deploy) = servers.deploy.as_mut() else {
        return Task::none();
    };
    if deploy.running() {
        return Task::none();
    }
    let Ok(request) = deploy.start(&profile) else {
        return Task::none();
    };

    let (task, handle) = Task::stream(crate::deploy::run(request)).abortable();
    servers.deploy_task = Some(handle.abort_on_drop());
    task
}

/// Ссылка ложится в редактор; набранное имя профиля остаётся.
fn finished(app: &mut App, result: Result<(), String>) {
    let servers = &mut app.state_mut().servers;
    servers.deploy_task = None;
    let Some(deploy) = servers.deploy.as_mut() else {
        return;
    };
    let Some(link) = deploy.finish(result) else {
        return;
    };

    match crate::forms::link::parse(&link) {
        Ok(mut draft) => {
            if let Some(name) = servers
                .editor
                .as_ref()
                .map(|typed| typed.name.clone())
                .filter(|name| !name.trim().is_empty())
            {
                draft.name = name;
            }
            servers.editor = Some(draft);
            servers.link = link;
            servers.deploy = None;
        }
        Err(reason) => deploy.error = Some(format!("{reason}: {link}")),
    }
}

/// Идущее развёртывание обрывается (процесс убит), иначе окно закрывается.
fn cancel(app: &mut App) {
    let servers = &mut app.state_mut().servers;
    match servers.deploy.as_mut() {
        Some(deploy) if deploy.running() => {
            servers.deploy_task = None;
            deploy.cancel();
        }
        _ => servers.deploy = None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::message::ServersMessage;
    use crate::app::update::profiles;
    use crate::forms::deploy::{Event, Field};

    fn pingwin_editor(name: &str) -> App {
        let (mut app, _task) = App::new(uikit::ThemeType::Dark, false);
        let _ = profiles::handle(&mut app, ServersMessage::PickerOpened);
        let _ = profiles::handle(&mut app, ServersMessage::ProtocolChosen("pingwin"));
        let _ = profiles::handle(&mut app, ServersMessage::EditorNameChanged(name.to_owned()));
        let _ = handle(&mut app, DeployMessage::Opened);
        app
    }

    fn deploy(app: &App) -> &Deploy {
        app.state().servers.deploy.as_ref().expect("окно открыто")
    }

    /// Как будто CLI запущен: задача не исполняется, состояние то же.
    fn running(app: &mut App) {
        for (field, value) in [
            (Field::Host, "203.0.113.5"),
            (Field::Domain, "vpn.example.com"),
        ] {
            let _ = handle(app, DeployMessage::Changed(field, value.to_owned()));
        }
        let _ = handle(app, DeployMessage::Started);
        assert!(deploy(app).running());
    }

    #[test]
    fn only_a_new_pingwin_profile_offers_deploying() {
        let mut app = pingwin_editor("");
        assert!(app.state().servers.deploy.is_some());

        let _ = handle(&mut app, DeployMessage::Cancelled);
        assert!(app.state().servers.deploy.is_none());
        assert!(app.state().servers.editor.is_some(), "редактор закрылся");

        let draft = app.state().servers.editor.clone().expect("редактор");
        assert!(!offers_deploy(&draft.with_id(Some("home".to_owned()))));
        assert!(!offers_deploy(&crate::forms::server::Draft::default()));
    }

    #[test]
    fn an_invalid_form_does_not_start() {
        let mut app = pingwin_editor("");
        let _ = handle(&mut app, DeployMessage::Started);
        assert!(!deploy(&app).running());
        assert!(app.state().servers.deploy_task.is_none());
    }

    #[test]
    fn cancelling_a_run_keeps_the_dialog_and_the_fields() {
        let mut app = pingwin_editor("");
        running(&mut app);
        assert!(app.state().servers.deploy_task.is_some());

        let _ = handle(&mut app, DeployMessage::Cancelled);
        assert!(app.state().servers.deploy_task.is_none());
        assert!(!deploy(&app).running());
        assert_eq!(deploy(&app).form.get(Field::Host), "203.0.113.5");
    }

    #[test]
    fn the_link_fills_the_editor_and_keeps_the_typed_name() {
        let mut app = pingwin_editor("Мой сервер");
        running(&mut app);
        let link = "pingwin://s3cret@vpn.example.com:443?key=AAAA#client";
        let _ = handle(&mut app, DeployMessage::Event(Event::Link(link.to_owned())));
        let _ = handle(&mut app, DeployMessage::Finished(Ok(())));

        let servers = &app.state().servers;
        assert!(servers.deploy.is_none());
        let draft = servers.editor.as_ref().expect("редактор");
        assert_eq!(draft.name, "Мой сервер");
        assert_eq!(draft.text("server"), "vpn.example.com:443");
        assert_eq!(draft.text("password"), "s3cret");
    }

    #[test]
    fn a_failure_stays_in_the_dialog() {
        let mut app = pingwin_editor("");
        running(&mut app);
        let _ = handle(&mut app, DeployMessage::Finished(Err("нет SSH".to_owned())));
        assert!(!deploy(&app).running());
        assert!(
            deploy(&app)
                .error
                .as_deref()
                .is_some_and(|e| e.contains("нет SSH"))
        );
    }
}
