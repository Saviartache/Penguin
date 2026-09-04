//! Профили и подписки на серверы.

use iced::Task;
use penguin_core::id::ProfileId;
use penguin_ipc::schema::Request;

use crate::app::App;
use crate::app::message::{Message, ServersMessage};
use crate::app::update::{request, save};
use crate::forms::server as editor;

/// Разбирает экран серверов.
pub fn handle(app: &mut App, message: ServersMessage) -> Task<Message> {
    match message {
        ServersMessage::SearchChanged(value) => {
            app.state_mut().servers.search = value;
            Task::none()
        }

        ServersMessage::Select(id) => {
            let profile = ProfileId::new(&id);

            // Выбор профиля сохраняется сразу, без «Сохранить»: это не правка
            // настроек, а действие — пользователь выбрал, куда подключаться.
            app.state_mut().config.active_profile = Some(profile.clone());

            Task::batch([
                save(app),
                // Если тоннель уже поднят, переключение профиля должно его
                // переподключить: иначе выбор ничего не изменит до следующего
                // запуска.
                if app.state().connection.tunnel.is_active() {
                    request(Request::Connect {
                        profile: Some(profile),
                    })
                } else {
                    Task::none()
                },
            ])
        }

        ServersMessage::Probe => {
            app.state_mut().servers.probing = true;
            app.state_mut().servers.latencies.clear();
            request(Request::Probe { profile: None })
        }

        ServersMessage::PickerOpened => {
            app.state_mut().servers.picker = true;
            app.state_mut().servers.link.clear();
            Task::none()
        }

        ServersMessage::PickerClosed => {
            app.state_mut().servers.picker = false;
            Task::none()
        }

        ServersMessage::ProtocolChosen(id) => {
            // Протокола нет в каталоге — значит, список собран не им, и
            // открывать нечего. Такого не бывает: список и есть каталог.
            let Some(spec) = crate::forms::protocol::by_id(id) else {
                return Task::none();
            };

            let state = app.state_mut();
            state.servers.picker = false;
            state.servers.editor = Some(editor::Draft::new(spec));
            state.servers.link.clear();
            Task::none()
        }

        ServersMessage::EditorOpened(id) => {
            // Профиль мог исчезнуть между отрисовкой списка и щелчком.
            let Some(profile) = app.state().config.profile(&ProfileId::new(&id)) else {
                return Task::none();
            };

            let draft = editor::Draft::from_profile(profile);
            let state = app.state_mut();
            state.servers.editor = Some(draft);
            state.servers.picker = false;
            state.servers.link.clear();
            Task::none()
        }

        ServersMessage::EditorClosed => {
            let state = app.state_mut();
            state.servers.editor = None;
            state.servers.link.clear();
            Task::none()
        }

        ServersMessage::LinkChanged(raw) => {
            let state = app.state_mut();
            state.servers.link = raw;

            // Разбирается только то, что похоже на ссылку. Пока человек
            // печатает, каждое нажатие клавиши давало бы новую ошибку — а он
            // ещё не закончил.
            if crate::forms::link::looks_like_link(&state.servers.link)
                && let Ok(draft) = crate::forms::link::parse(&state.servers.link)
            {
                // Правка существующего профиля сохраняет его идентификатор: на
                // него ссылаются правила, и вставка ссылки не должна их
                // ломать.
                let id = state
                    .servers
                    .editor
                    .as_ref()
                    .and_then(|open| open.id.clone());
                state.servers.editor = Some(draft.with_id(id));
            }
            Task::none()
        }

        ServersMessage::EditorNameChanged(value) => {
            if let Some(draft) = app.state_mut().servers.editor.as_mut() {
                draft.name = value;
            }
            Task::none()
        }

        ServersMessage::EditorChanged(index, value) => {
            if let Some(draft) = app.state_mut().servers.editor.as_mut() {
                draft.set_at(index, value);
            }
            Task::none()
        }

        ServersMessage::EditorToggled(index, value) => {
            if let Some(draft) = app.state_mut().servers.editor.as_mut() {
                draft.toggle_at(index, value);
            }
            Task::none()
        }

        ServersMessage::EditorSubmitted => {
            let Some(draft) = app.state().servers.editor.as_ref() else {
                return Task::none();
            };
            // Неверный черновик не сохраняется молча: причина уже видна в
            // самом редакторе, и закрывать его значило бы её спрятать.
            let Ok(profile) = draft.to_profile() else {
                return Task::none();
            };

            let state = app.state_mut();
            match state
                .config
                .profiles
                .iter_mut()
                .find(|known| known.id == profile.id)
            {
                Some(existing) => *existing = profile,
                None => state.config.profiles.push(profile),
            }
            state.servers.editor = None;
            state.servers.link.clear();

            save(app)
        }

        ServersMessage::Removed(id) => {
            let profile = ProfileId::new(&id);
            let state = app.state_mut();

            state.config.profiles.retain(|known| known.id != profile);
            state.servers.editor = None;
            // Активный профиль удалён — выбор снимается, и активным
            // становится первый в списке: указывать на удалённый нельзя.
            if state.config.active_profile.as_ref() == Some(&profile) {
                state.config.active_profile = None;
            }

            save(app)
        }
    }
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::outbound::RawOutbound;
    use penguin_config::schema::profile::Profile;
    use serde_json::json;

    use super::*;

    fn app_with_profiles(ids: &[&str]) -> App {
        let (mut app, _task) = App::new(uikit::ThemeType::Dark);
        for id in ids {
            app.state_mut().config.profiles.push(Profile::new(
                *id,
                *id,
                RawOutbound::new(
                    "hysteria2",
                    json!({ "server": "example.com:443", "auth": "x" }),
                ),
            ));
        }
        app
    }

    /// Открытый черновик.
    fn draft(app: &App) -> &editor::Draft {
        app.state()
            .servers
            .editor
            .as_ref()
            .expect("редактор открыт")
    }

    /// Набирает одно поле открытой формы по его имени.
    fn field(app: &mut App, key: &str, value: &str) {
        let index = draft(app)
            .spec()
            .and_then(|spec| spec.index_of(key))
            .expect("поле есть в форме");
        let _ = handle(app, ServersMessage::EditorChanged(index, value.to_owned()));
    }

    /// Открывает форму нового профиля указанного протокола.
    fn new_profile(app: &mut App, protocol: &'static str) {
        let _ = handle(app, ServersMessage::PickerOpened);
        let _ = handle(app, ServersMessage::ProtocolChosen(protocol));
    }

    #[test]
    fn selecting_a_profile_records_it() {
        // Это не правка настроек, а действие: пользователь выбрал, куда
        // подключаться, и ждать «Сохранить» здесь неуместно.
        let mut app = app_with_profiles(&["home", "office"]);
        let _ = handle(&mut app, ServersMessage::Select("office".to_owned()));

        assert_eq!(
            app.state()
                .config
                .active_profile
                .as_ref()
                .map(ProfileId::as_str),
            Some("office")
        );
    }

    #[test]
    fn probing_clears_previous_results() {
        // Старые задержки рядом с крутящимся индикатором читаются как
        // свежие — а они уже неверны.
        let mut app = app_with_profiles(&["home"]);
        app.state_mut().servers.latencies = vec![("home".to_owned(), Some(42))];

        let _ = handle(&mut app, ServersMessage::Probe);

        assert!(app.state().servers.probing);
        assert!(app.state().servers.latencies.is_empty());
    }

    #[test]
    fn adding_a_server_asks_for_the_protocol_first() {
        // Полей у формы нет, пока не известно, чьи они.
        let mut app = app_with_profiles(&[]);
        let _ = handle(&mut app, ServersMessage::PickerOpened);

        assert!(app.state().servers.picker);
        assert!(
            app.state().servers.editor.is_none(),
            "форма открылась раньше выбора"
        );
    }

    #[test]
    fn choosing_a_protocol_opens_its_form() {
        let mut app = app_with_profiles(&[]);
        new_profile(&mut app, "socks5");

        assert!(!app.state().servers.picker, "список остался открытым");
        let draft = draft(&app);
        assert!(!draft.is_edit());
        assert_eq!(draft.protocol(), "socks5");
        assert!(
            draft
                .spec()
                .is_some_and(|spec| spec.index_of("udp").is_some()),
            "в форме нет полей SOCKS5"
        );
    }

    #[test]
    fn closing_the_picker_opens_nothing() {
        let mut app = app_with_profiles(&[]);
        let _ = handle(&mut app, ServersMessage::PickerOpened);
        let _ = handle(&mut app, ServersMessage::PickerClosed);

        assert!(!app.state().servers.picker);
        assert!(app.state().servers.editor.is_none());
    }

    #[test]
    fn opening_the_editor_on_a_profile_fills_it() {
        // Пустая форма на правке существующего профиля означала бы, что
        // сохранение стирает всё, чего в ней не набрали заново.
        let mut app = app_with_profiles(&["home"]);
        let _ = handle(&mut app, ServersMessage::EditorOpened("home".to_owned()));

        let draft = draft(&app);
        assert!(draft.is_edit());
        assert_eq!(draft.text("server"), "example.com:443");
        assert_eq!(draft.text("password"), "x", "пароль обязан подхватиться");
    }

    #[test]
    fn an_unknown_identifier_opens_nothing() {
        // Список мог измениться между отрисовкой и щелчком; открывать пустую
        // форму на месте правки значило бы завести профиль из ничего.
        let mut app = app_with_profiles(&["home"]);
        let _ = handle(
            &mut app,
            ServersMessage::EditorOpened("нет такого".to_owned()),
        );

        assert!(app.state().servers.editor.is_none());
    }

    #[test]
    fn saving_a_new_profile_adds_it() {
        let mut app = app_with_profiles(&[]);
        new_profile(&mut app, "hysteria2");
        let _ = handle(
            &mut app,
            ServersMessage::EditorNameChanged("Офис".to_owned()),
        );
        field(&mut app, "server", "office.example.com:443");
        field(&mut app, "password", "секрет");

        let _ = handle(&mut app, ServersMessage::EditorSubmitted);

        assert_eq!(app.state().config.profiles.len(), 1);
        assert_eq!(app.state().config.profiles[0].name, "Офис");
        assert!(
            app.state().servers.editor.is_none(),
            "редактор должен закрыться"
        );
    }

    #[test]
    fn saving_a_proxy_profile_writes_its_protocol() {
        // Ради этого выбор протокола и заводился: сохраниться обязан тот, что
        // выбрали, а не тот, что был первым.
        let mut app = app_with_profiles(&[]);
        new_profile(&mut app, "socks5");
        field(&mut app, "server", "127.0.0.1:1080");

        let _ = handle(&mut app, ServersMessage::EditorSubmitted);

        let profile = &app.state().config.profiles[0];
        assert_eq!(profile.outbound.protocol, "socks5");
        assert_eq!(
            profile.outbound.field("server").and_then(|v| v.as_str()),
            Some("127.0.0.1:1080")
        );
    }

    #[test]
    fn a_flag_is_toggled_by_its_place_in_the_form() {
        let mut app = app_with_profiles(&[]);
        new_profile(&mut app, "socks5");
        field(&mut app, "server", "127.0.0.1:1080");

        let index = draft(&app)
            .spec()
            .and_then(|spec| spec.index_of("udp"))
            .expect("поле есть");
        let _ = handle(&mut app, ServersMessage::EditorToggled(index, false));
        let _ = handle(&mut app, ServersMessage::EditorSubmitted);

        assert_eq!(
            app.state().config.profiles[0]
                .outbound
                .field("udp")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn saving_an_edited_profile_replaces_it_instead_of_adding() {
        let mut app = app_with_profiles(&["home"]);
        let _ = handle(&mut app, ServersMessage::EditorOpened("home".to_owned()));
        let _ = handle(
            &mut app,
            ServersMessage::EditorNameChanged("Дом (новый)".to_owned()),
        );

        let _ = handle(&mut app, ServersMessage::EditorSubmitted);

        assert_eq!(
            app.state().config.profiles.len(),
            1,
            "профиль не должен раздвоиться"
        );
        assert_eq!(app.state().config.profiles[0].name, "Дом (новый)");
    }

    #[test]
    fn an_invalid_draft_keeps_the_editor_open() {
        // Причина уже видна в самой форме; закрыть её значило бы спрятать
        // ошибку и молча ничего не сохранить.
        let mut app = app_with_profiles(&[]);
        new_profile(&mut app, "hysteria2");
        let _ = handle(&mut app, ServersMessage::EditorSubmitted);

        assert!(app.state().config.profiles.is_empty());
        assert!(app.state().servers.editor.is_some());
    }

    #[test]
    fn removing_the_active_profile_clears_the_choice() {
        // Указывать на удалённый профиль нельзя: демон полез бы за ним и не
        // нашёл.
        let mut app = app_with_profiles(&["home", "office"]);
        let _ = handle(&mut app, ServersMessage::Select("home".to_owned()));

        let _ = handle(&mut app, ServersMessage::Removed("home".to_owned()));

        assert_eq!(app.state().config.profiles.len(), 1);
        assert!(app.state().config.active_profile.is_none());
        // Активным становится первый в списке — им и остаётся выбор.
        assert_eq!(
            app.state().config.active().map(|p| p.id.as_str()),
            Some("office")
        );
    }

    #[test]
    fn removing_another_profile_keeps_the_choice() {
        let mut app = app_with_profiles(&["home", "office"]);
        let _ = handle(&mut app, ServersMessage::Select("home".to_owned()));

        let _ = handle(&mut app, ServersMessage::Removed("office".to_owned()));

        assert_eq!(
            app.state()
                .config
                .active_profile
                .as_ref()
                .map(ProfileId::as_str),
            Some("home")
        );
    }

    /// Ссылка из задачи — та, ради которой импорт и заводился.
    const LINK: &str =
        "hy2://source:s3cret@example.net:3478?sni=example.net&alpn=h3&insecure=0#source";

    #[test]
    fn a_pasted_link_fills_the_form() {
        // Ради этого импорт и заводился: вставил — остальное заполнилось само.
        let mut app = app_with_profiles(&[]);
        new_profile(&mut app, "hysteria2");
        let _ = handle(&mut app, ServersMessage::LinkChanged(LINK.to_owned()));

        let draft = draft(&app);
        assert_eq!(draft.text("server"), "example.net:3478");
        assert_eq!(draft.text("password"), "source:s3cret");
        assert_eq!(draft.text("sni"), "example.net");
        assert_eq!(draft.name, "source");
        assert!(!draft.flag("insecure"));
    }

    #[test]
    fn a_pasted_link_switches_the_protocol_to_its_own() {
        // Ссылка знает свой протокол лучше, чем тот, кого выбрали до неё.
        let mut app = app_with_profiles(&[]);
        new_profile(&mut app, "hysteria2");
        let _ = handle(
            &mut app,
            ServersMessage::LinkChanged("socks5://127.0.0.1:1080#Дома".to_owned()),
        );

        assert_eq!(draft(&app).protocol(), "socks5");
    }

    #[test]
    fn a_pasted_link_saves_as_a_profile() {
        // Заполнить форму мало: профиль обязан дойти до списка.
        let mut app = app_with_profiles(&[]);
        new_profile(&mut app, "hysteria2");
        let _ = handle(
            &mut app,
            ServersMessage::LinkChanged("hy2://pass@example.net:3478#Орландо".to_owned()),
        );
        let _ = handle(&mut app, ServersMessage::EditorSubmitted);

        assert_eq!(app.state().config.profiles.len(), 1);
        assert_eq!(app.state().config.profiles[0].name, "Орландо");
        assert!(app.state().servers.link.is_empty(), "ссылка не убрана");
    }

    #[test]
    fn a_link_pasted_while_editing_keeps_the_identifier() {
        // На идентификатор ссылаются правила: замена сервера по ссылке не
        // должна их ломать.
        let mut app = app_with_profiles(&["home"]);
        let _ = handle(&mut app, ServersMessage::EditorOpened("home".to_owned()));
        let _ = handle(
            &mut app,
            ServersMessage::LinkChanged("hy2://pass@other.example.com:443#Другой".to_owned()),
        );

        let draft = draft(&app);
        assert_eq!(draft.id.as_deref(), Some("home"));
        assert_eq!(draft.text("server"), "other.example.com:443");
    }

    #[test]
    fn typing_a_name_is_not_taken_for_a_link() {
        // Разбирать каждое нажатие клавиши и показывать ошибку на каждой букве
        // — худший способ помочь.
        let mut app = app_with_profiles(&[]);
        new_profile(&mut app, "hysteria2");
        let _ = handle(&mut app, ServersMessage::LinkChanged("Дом".to_owned()));

        assert!(
            draft(&app).text("server").is_empty(),
            "форма заполнилась из не-ссылки"
        );
    }

    #[test]
    fn closing_the_editor_discards_the_draft() {
        let mut app = app_with_profiles(&["home"]);
        let _ = handle(&mut app, ServersMessage::EditorOpened("home".to_owned()));
        let _ = handle(
            &mut app,
            ServersMessage::EditorNameChanged("не сохранится".to_owned()),
        );

        let _ = handle(&mut app, ServersMessage::EditorClosed);

        assert!(app.state().servers.editor.is_none());
        assert_eq!(app.state().config.profiles[0].name, "home");
    }

    #[test]
    fn a_profile_of_an_unknown_protocol_still_opens() {
        // Настройки мог написать человек или прислать новая версия. Кнопка,
        // которая ничего не делает, читается как сломанная.
        let mut app = app_with_profiles(&[]);
        app.state_mut().config.profiles.push(Profile::new(
            "чужой",
            "Чужой",
            RawOutbound::new("телепатия", json!({ "server": "example.com:443" })),
        ));

        let _ = handle(&mut app, ServersMessage::EditorOpened("чужой".to_owned()));

        let draft = draft(&app);
        assert!(draft.spec().is_none());
        assert!(draft.fields().is_empty());
    }
}
