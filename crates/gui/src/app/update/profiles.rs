//! Профили и подписки на серверы.

use iced::Task;
use penguin_core::id::ProfileId;
use penguin_ipc::schema::{LogLevel, Request, Response};

use crate::app::App;
use crate::app::countries::Countries;
use crate::app::message::{IpcMessage, Message, ServersMessage};
use crate::app::probe_queue::ProbeQueue;
use crate::app::update::{request, save};
use crate::forms::server as editor;
use crate::screens::servers::server_of;

/// Разбирает экран серверов.
pub fn handle(app: &mut App, message: ServersMessage) -> Task<Message> {
    match message {
        ServersMessage::SearchChanged(value) => {
            app.state_mut().servers.search = value;
            Task::none()
        }
        ServersMessage::Select(id) => select(app, &id),
        ServersMessage::Probe => {
            let state = app.state_mut();
            let ids = state.config.profiles.iter().map(|p| p.id.to_string());
            state.servers.probe.start(ids);
            probe_current(&app.state().servers.probe)
        }
        ServersMessage::ProbeFailed(profile, message) => probe_failed(app, &profile, message),
        ServersMessage::PickerOpened => {
            app.state_mut().servers.picker = true;
            app.state_mut().servers.link.clear();
            Task::none()
        }
        ServersMessage::PickerClosed => {
            app.state_mut().servers.picker = false;
            Task::none()
        }
        ServersMessage::ProtocolChosen(id) => choose_protocol(app, id),
        ServersMessage::EditorOpened(id) => open_editor(app, &id),
        ServersMessage::EditorClosed => {
            let state = app.state_mut();
            state.servers.editor = None;
            state.servers.link.clear();
            Task::none()
        }
        ServersMessage::LinkChanged(raw) => paste_link(app, raw),
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
        ServersMessage::EditorSubmitted => submit(app),
        ServersMessage::Removed(id) => remove(app, &id),
        ServersMessage::WireguardManual => wireguard_manual(app),
        ServersMessage::WireguardFromConf => wireguard_from_conf(app),
        ServersMessage::ConfImported(result) => conf_imported(app, result),
        ServersMessage::WireguardClosed => {
            close_wireguard(app);
            Task::none()
        }
        ServersMessage::SubscriptionKeyChanged(value) => {
            app.state_mut().servers.subscription_key = value;
            Task::none()
        }
        ServersMessage::SubscriptionRefresh => subscription_refresh(app),
        ServersMessage::SubscriptionRefreshed(result) => subscription_refreshed(app, result),
        ServersMessage::CountriesLocated(asked, result) => countries_located(app, &asked, result),
    }
}

/// Спрашивает страну серверов, о которых ещё не спрашивали; флаги — по ответу.
pub(crate) fn locate_countries(app: &mut App) -> Task<Message> {
    let state = app.state_mut();
    let servers = Countries::wanted(&state.config.profiles);
    let asked = state.servers.countries.unasked(servers);
    if asked.is_empty() {
        return Task::none();
    }
    Task::perform(crate::geoip::locate(asked.clone()), move |result| {
        Message::Servers(ServersMessage::CountriesLocated(asked.clone(), result))
    })
}

fn countries_located(
    app: &mut App,
    asked: &[String],
    result: Result<std::collections::HashMap<String, String>, String>,
) -> Task<Message> {
    let state = app.state_mut();
    match result {
        Ok(found) => state.servers.countries.located(found),
        Err(reason) => {
            state.servers.countries.failed(asked);
            state.connection.push_log(
                LogLevel::Warning,
                format!("{}: {reason}", crate::i18n::s().countries_failed),
            );
        }
    }
    Task::none()
}

/// Открывает форму WireGuard вручную из окна выбора способа.
fn wireguard_manual(app: &mut App) -> Task<Message> {
    let Some(spec) = crate::forms::protocol::by_id("wireguard") else {
        return Task::none();
    };
    close_wireguard(app);
    app.state_mut().servers.editor = Some(editor::Draft::new(spec));
    Task::none()
}

/// Спрашивает файл `.conf` и разбирает его в отдельном потоке (окно держит поток).
fn wireguard_from_conf(app: &mut App) -> Task<Message> {
    if app.state().servers.subscription_busy {
        return Task::none();
    }
    app.state_mut().servers.subscription_busy = true;
    Task::perform(read_conf(), |result| {
        Message::Servers(ServersMessage::ConfImported(result))
    })
}

/// Заводит профиль из `.conf`; отмена — не ошибка, ошибка — в журнал.
fn conf_imported(
    app: &mut App,
    result: Result<Option<penguin_config::schema::profile::Profile>, String>,
) -> Task<Message> {
    app.state_mut().servers.subscription_busy = false;
    match result {
        Ok(None) => Task::none(),
        Ok(Some(profile)) => {
            close_wireguard(app);
            add_or_replace(app, profile);
            save(app)
        }
        Err(reason) => {
            app.state_mut().connection.push_log(
                LogLevel::Error,
                format!("{}: {reason}", crate::i18n::s().import_conf_failed),
            );
            Task::none()
        }
    }
}

/// Закрывает окно добавления WireGuard и чистит ключ подписки.
fn close_wireguard(app: &mut App) {
    let state = app.state_mut();
    state.servers.wireguard = false;
    state.servers.subscription_key.clear();
}

/// Добавляет профиль или заменяет существующий с тем же идентификатором.
fn add_or_replace(app: &mut App, profile: penguin_config::schema::profile::Profile) {
    let profiles = &mut app.state_mut().config.profiles;
    match profiles.iter_mut().find(|known| known.id == profile.id) {
        Some(existing) => *existing = profile,
        None => profiles.push(profile),
    }
}

/// Спрашивает `.conf` и разбирает его в профиль; `None` — окно закрыли без выбора.
async fn read_conf() -> Result<Option<penguin_config::schema::profile::Profile>, String> {
    use penguin_config::import::parse_wireguard_conf;
    use penguin_config::schema::profile::Profile;

    let title = crate::i18n::s().import_conf_title;
    let filter = crate::i18n::s().wireguard_configs;
    let unreadable = crate::i18n::s().import_conf_failed;

    let read = tokio::task::spawn_blocking(move || {
        let Some(path) = penguin_platform::dialog::pick_wireguard_config(title, filter)
            .map_err(|err| err.to_string())?
        else {
            return Ok(None);
        };
        let text = std::fs::read_to_string(&path).map_err(|err| format!("{unreadable}: {err}"))?;
        let outbound = parse_wireguard_conf(&text).map_err(|err| err.to_string())?;
        let name = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "WireGuard".to_owned());
        Ok(Some(Profile::new(editor::slug(&name), name, outbound)))
    })
    .await;

    read.unwrap_or_else(|err| Err(err.to_string()))
}

/// Просит себя-как-CLI забрать серверы по ключу; пустой ключ ничего не делает.
fn subscription_refresh(app: &mut App) -> Task<Message> {
    let key = app.state().servers.subscription_key.trim().to_owned();
    if key.is_empty() || app.state().servers.subscription_busy {
        return Task::none();
    }
    app.state_mut().servers.subscription_busy = true;
    Task::perform(crate::subscription::refresh(key), |result| {
        Message::Servers(ServersMessage::SubscriptionRefreshed(result))
    })
}

/// Вливает присланные профили, заменяя управляемые той же подпиской.
fn subscription_refreshed(
    app: &mut App,
    result: Result<Vec<penguin_config::schema::profile::Profile>, String>,
) -> Task<Message> {
    app.state_mut().servers.subscription_busy = false;
    let strings = crate::i18n::s();
    match result {
        Ok(profiles) => {
            let count = profiles.len();
            merge_managed(app, profiles);
            close_wireguard(app);
            let state = app.state_mut();
            state.servers.picker = false;
            state.connection.push_log(
                LogLevel::Info,
                format!("{}: {count}", strings.subscription_updated),
            );
            save(app)
        }
        Err(reason) => {
            app.state_mut().connection.push_log(
                LogLevel::Error,
                format!("{}: {reason}", strings.subscription_failed),
            );
            Task::none()
        }
    }
}

/// Заменяет управляемые профили подписок свежим набором (по `subscription`).
pub(crate) fn merge_managed(
    app: &mut App,
    profiles: Vec<penguin_config::schema::profile::Profile>,
) {
    let ids: std::collections::BTreeSet<String> = profiles
        .iter()
        .filter_map(|profile| profile.subscription.clone())
        .collect();
    let config = &mut app.state_mut().config;
    config
        .profiles
        .retain(|profile| match &profile.subscription {
            Some(id) => !ids.contains(id),
            None => true,
        });
    config.profiles.extend(profiles);
    if let Some(active) = config.active_profile.clone()
        && config.profile(&active).is_none()
    {
        config.active_profile = None;
    }
}

/// Выбор сохраняется сразу; поднятый тоннель переподключается на новый профиль.
/// Просит проверить профиль, на котором стоит очередь.
///
/// Ошибка уходит отдельным сообщением: чужая ошибка прогон не обрывает.
pub fn probe_current(queue: &ProbeQueue) -> Task<Message> {
    let Some(id) = queue.current().map(str::to_owned) else {
        return Task::none();
    };
    let probe = Request::Probe {
        profile: Some(ProfileId::new(&id)),
    };
    Task::perform(
        crate::ipc::client::send_or_error(probe),
        move |response| match response {
            Response::Error { message, .. } => {
                Message::Servers(ServersMessage::ProbeFailed(id.clone(), message))
            }
            other => Message::Ipc(IpcMessage::Response(Box::new(other))),
        },
    )
}

/// Ошибка своего прогона останавливает его: дальше по очереди будет та же.
fn probe_failed(app: &mut App, profile: &str, message: String) -> Task<Message> {
    let state = app.state_mut();
    if state.servers.probe.current() == Some(profile) {
        state.servers.probe.cancel();
    }
    state.connection.push_log(LogLevel::Error, message);
    Task::none()
}

fn select(app: &mut App, id: &str) -> Task<Message> {
    let profile = ProfileId::new(id);
    app.state_mut().config.active_profile = Some(profile.clone());

    Task::batch([
        save(app),
        if app.state().connection.tunnel.is_active() {
            request(Request::Connect {
                profile: Some(profile),
            })
        } else {
            Task::none()
        },
    ])
}

fn choose_protocol(app: &mut App, id: &str) -> Task<Message> {
    // Список и есть каталог, чужого id быть не может.
    let Some(spec) = crate::forms::protocol::by_id(id) else {
        return Task::none();
    };

    let state = app.state_mut();
    state.servers.picker = false;
    state.servers.link.clear();
    // У WireGuard три способа добавить: вручную, из `.conf`, подпиской.
    if id == "wireguard" {
        state.servers.wireguard = true;
        state.servers.subscription_key.clear();
    } else {
        state.servers.editor = Some(editor::Draft::new(spec));
    }
    Task::none()
}

fn open_editor(app: &mut App, id: &str) -> Task<Message> {
    // Профиль мог исчезнуть между отрисовкой и щелчком.
    let Some(profile) = app.state().config.profile(&ProfileId::new(id)) else {
        return Task::none();
    };

    let draft = editor::Draft::from_profile(profile);
    let state = app.state_mut();
    state.servers.editor = Some(draft);
    state.servers.picker = false;
    state.servers.link.clear();
    Task::none()
}

/// Разбирается только похожее на ссылку: иначе каждая буква давала бы ошибку.
/// Идентификатор правящегося профиля сохраняется: на него ссылаются правила.
fn paste_link(app: &mut App, raw: String) -> Task<Message> {
    let state = app.state_mut();
    state.servers.link = raw;

    if crate::forms::link::looks_like_link(&state.servers.link)
        && let Ok(draft) = crate::forms::link::parse(&state.servers.link)
    {
        let id = state
            .servers
            .editor
            .as_ref()
            .and_then(|open| open.id.clone());
        state.servers.editor = Some(draft.with_id(id));
    }
    Task::none()
}

fn submit(app: &mut App) -> Task<Message> {
    let Some(draft) = app.state().servers.editor.as_ref() else {
        return Task::none();
    };
    // Неверный черновик не закрывается: причина видна в редакторе.
    let Ok(mut profile) = draft.to_profile() else {
        return Task::none();
    };

    let state = app.state_mut();
    match state
        .config
        .profiles
        .iter_mut()
        .find(|known| known.id == profile.id)
    {
        Some(existing) => {
            // Формы у них нет: без переноса правка отвязала бы профиль от подписки.
            profile.subscription = existing.subscription.take();
            profile.tags = std::mem::take(&mut existing.tags);
            // Страна источника верна, пока адрес тот же.
            if server_of(existing) == server_of(&profile) {
                profile.country = existing.country.take();
            }
            *existing = profile;
        }
        None => state.config.profiles.push(profile),
    }
    state.servers.editor = None;
    state.servers.link.clear();

    save(app)
}

/// Удаляет профиль; выбор на удалённый снимается (активным станет первый).
fn remove(app: &mut App, id: &str) -> Task<Message> {
    let profile = ProfileId::new(id);
    let state = app.state_mut();

    state.config.profiles.retain(|known| known.id != profile);
    state.servers.editor = None;
    if state.config.active_profile.as_ref() == Some(&profile) {
        state.config.active_profile = None;
    }

    save(app)
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::outbound::RawOutbound;
    use penguin_config::schema::profile::Profile;
    use serde_json::json;

    use super::*;

    fn app_with_profiles(ids: &[&str]) -> App {
        let (mut app, _task) = App::new(uikit::ThemeType::Dark, false);
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

    fn draft(app: &App) -> &editor::Draft {
        app.state()
            .servers
            .editor
            .as_ref()
            .expect("редактор открыт")
    }

    /// Набирает поле открытой формы по имени.
    fn field(app: &mut App, key: &str, value: &str) {
        let index = draft(app)
            .spec()
            .and_then(|spec| spec.index_of(key))
            .expect("поле есть в форме");
        let _ = handle(app, ServersMessage::EditorChanged(index, value.to_owned()));
    }

    fn new_profile(app: &mut App, protocol: &'static str) {
        let _ = handle(app, ServersMessage::PickerOpened);
        let _ = handle(app, ServersMessage::ProtocolChosen(protocol));
    }

    #[test]
    fn selecting_a_profile_records_it() {
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
    fn probing_starts_with_the_first_profile_and_keeps_old_results() {
        let mut app = app_with_profiles(&["home", "work"]);
        app.state_mut().servers.latencies = vec![("work".to_owned(), Some(42))];

        let _ = handle(&mut app, ServersMessage::Probe);

        assert_eq!(app.state().servers.probe.current(), Some("home"));
        assert_eq!(app.state().servers.latencies.len(), 1);
    }

    #[test]
    fn only_an_error_of_the_current_probe_stops_the_run() {
        let mut app = app_with_profiles(&["home", "work"]);
        let _ = handle(&mut app, ServersMessage::Probe);

        let stale = ServersMessage::ProbeFailed("work".to_owned(), "старый".to_owned());
        let _ = handle(&mut app, stale);
        assert_eq!(app.state().servers.probe.current(), Some("home"));

        let own = ServersMessage::ProbeFailed("home".to_owned(), "нет связи".to_owned());
        let _ = handle(&mut app, own);
        assert!(!app.state().servers.probe.is_running());
    }

    #[test]
    fn adding_a_server_asks_for_the_protocol_first() {
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
        let mut app = app_with_profiles(&["home"]);
        let _ = handle(&mut app, ServersMessage::EditorOpened("home".to_owned()));

        let draft = draft(&app);
        assert!(draft.is_edit());
        assert_eq!(draft.text("server"), "example.com:443");
        assert_eq!(draft.text("password"), "x", "пароль обязан подхватиться");
    }

    #[test]
    fn an_unknown_identifier_opens_nothing() {
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
    fn editing_a_subscription_profile_keeps_it_managed() {
        let mut app = app_with_profiles(&["home"]);
        let profile = &mut app.state_mut().config.profiles[0];
        profile.subscription = Some("amnezia-1".to_owned());
        profile.tags = vec!["работа".to_owned()];

        let _ = handle(&mut app, ServersMessage::EditorOpened("home".to_owned()));
        let _ = handle(
            &mut app,
            ServersMessage::EditorNameChanged("Дом".to_owned()),
        );
        let _ = handle(&mut app, ServersMessage::EditorSubmitted);

        let saved = &app.state().config.profiles[0];
        assert_eq!(saved.name, "Дом");
        assert_eq!(saved.subscription.as_deref(), Some("amnezia-1"));
        assert_eq!(saved.tags, vec!["работа".to_owned()]);
    }

    #[test]
    fn an_invalid_draft_keeps_the_editor_open() {
        let mut app = app_with_profiles(&[]);
        new_profile(&mut app, "hysteria2");
        let _ = handle(&mut app, ServersMessage::EditorSubmitted);

        assert!(app.state().config.profiles.is_empty());
        assert!(app.state().servers.editor.is_some());
    }

    fn managed(id: &str, sub: &str) -> Profile {
        let mut profile = Profile::new(id, id, RawOutbound::new("wireguard", json!({})));
        profile.subscription = Some(sub.to_owned());
        profile
    }

    #[test]
    fn a_subscription_refresh_replaces_only_its_own_profiles() {
        let mut app = app_with_profiles(&["home"]);
        app.state_mut()
            .config
            .profiles
            .push(managed("old-nl", "amnezia-1"));
        app.state_mut().servers.subscription_busy = true;

        let _ = subscription_refreshed(&mut app, Ok(vec![managed("new-de", "amnezia-1")]));

        let ids: Vec<&str> = app
            .state()
            .config
            .profiles
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(ids, vec!["home", "new-de"], "старый управляемый не убран");
        assert!(!app.state().servers.subscription_busy);
    }

    #[test]
    fn a_failed_subscription_refresh_clears_the_flag_and_logs() {
        let mut app = app_with_profiles(&[]);
        app.state_mut().servers.subscription_busy = true;
        let before = app.state().connection.log.len();

        let _ = subscription_refreshed(&mut app, Err("шлюз недоступен".to_owned()));

        assert!(!app.state().servers.subscription_busy);
        assert_eq!(app.state().connection.log.len(), before + 1);
    }

    #[test]
    fn removing_the_active_profile_clears_the_choice() {
        let mut app = app_with_profiles(&["home", "office"]);
        let _ = handle(&mut app, ServersMessage::Select("home".to_owned()));

        let _ = handle(&mut app, ServersMessage::Removed("home".to_owned()));

        assert_eq!(app.state().config.profiles.len(), 1);
        assert!(app.state().config.active_profile.is_none());
        // Активным становится первый в списке.
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

    const LINK: &str =
        "hy2://source:s3cret@example.net:3478?sni=example.net&alpn=h3&insecure=0#source";

    #[test]
    fn a_pasted_link_fills_the_form() {
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
