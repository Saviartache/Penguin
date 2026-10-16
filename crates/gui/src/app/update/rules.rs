//! Правка правил раздельного тоннелирования.
//!
//! Правки копятся в окне и уезжают демону только по «Сохранить»: иначе каждый
//! щелчок перезаписывал бы файл и пересобирал набор.

use iced::Task;
use penguin_config::schema::rule::RuleConfig;
use penguin_ipc::schema::Request;

use crate::app::App;
use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::update::{request, save_rules};
use crate::forms::rule;

/// Разбирает экран правил.
pub fn handle(app: &mut App, message: SplitTunnelMessage) -> Task<Message> {
    match message {
        SplitTunnelMessage::ModeSelected(mode) => {
            if app.state().config.routing.mode != mode {
                app.state_mut().config.routing.mode = mode;
                app.state_mut().dirty = true;
            }
            Task::none()
        }
        SplitTunnelMessage::RuleMoved(from, to) => {
            if move_rule(&mut app.state_mut().config.routing.rules, from, to) {
                app.state_mut().dirty = true;
            }
            Task::none()
        }
        SplitTunnelMessage::SearchChanged(value) => {
            app.state_mut().split_tunnel.search = value;
            Task::none()
        }
        SplitTunnelMessage::RuleToggled(index, enabled) => {
            if let Some(rule) = app.state_mut().config.routing.rules.get_mut(index) {
                rule.enabled = enabled;
                app.state_mut().dirty = true;
            }
            Task::none()
        }
        SplitTunnelMessage::RuleRemoved(index) => {
            let rules = &mut app.state_mut().config.routing.rules;
            if index < rules.len() {
                rules.remove(index);
                app.state_mut().dirty = true;
            }
            Task::none()
        }
        SplitTunnelMessage::ProbeOpened => {
            app.state_mut().split_tunnel.probe_open = true;
            Task::none()
        }
        SplitTunnelMessage::ProbeClosed => {
            app.state_mut().split_tunnel.probe_open = false;
            Task::none()
        }
        SplitTunnelMessage::ProbeDestinationChanged(value) => {
            app.state_mut().split_tunnel.probe_destination = value;
            Task::none()
        }
        SplitTunnelMessage::ProbeProcessChanged(value) => {
            app.state_mut().split_tunnel.probe_process = value;
            Task::none()
        }
        SplitTunnelMessage::ProbeRequested => probe(app),
        SplitTunnelMessage::EditorOpened(index) => open_editor(app, index),
        SplitTunnelMessage::EditorClosed => {
            app.state_mut().split_tunnel.editor = None;
            Task::none()
        }
        SplitTunnelMessage::AppSearchChanged(value) => {
            app.state_mut().split_tunnel.app_search = value;
            Task::none()
        }
        SplitTunnelMessage::AppToggled(path, checked) => {
            if let Some(draft) = app.state_mut().split_tunnel.editor.as_mut() {
                draft.toggle_process(&path, checked);
            }
            Task::none()
        }
        SplitTunnelMessage::AppPickRequested => pick(app),
        SplitTunnelMessage::AppPicked(picked) => picked_file(app, picked),
        SplitTunnelMessage::DraftNameChanged(value) => {
            if let Some(draft) = app.state_mut().split_tunnel.editor.as_mut() {
                draft.name = value;
            }
            Task::none()
        }
        SplitTunnelMessage::DraftHostsChanged(value) => {
            if let Some(draft) = app.state_mut().split_tunnel.editor.as_mut() {
                draft.hosts = value;
            }
            Task::none()
        }
        SplitTunnelMessage::DraftPortsChanged(value) => {
            if let Some(draft) = app.state_mut().split_tunnel.editor.as_mut() {
                draft.ports = value;
            }
            Task::none()
        }
        SplitTunnelMessage::DraftActionSelected(action) => {
            if let Some(draft) = app.state_mut().split_tunnel.editor.as_mut() {
                draft.action = action;
            }
            Task::none()
        }
        SplitTunnelMessage::DraftSaved => save_draft(app),
        SplitTunnelMessage::Save => save_rules(app),
    }
}

fn probe(app: &App) -> Task<Message> {
    let state = &app.state().split_tunnel;
    if state.probe_destination.trim().is_empty() {
        return Task::none();
    }

    let process = Some(state.probe_process.trim().to_owned()).filter(|value| !value.is_empty());

    request(Request::Explain {
        destination: state.probe_destination.trim().to_owned(),
        process,
        udp: false,
    })
}

/// Открывает окно группы: поиск и жалоба от прошлого не переносятся, список
/// запущенного мог устареть. Правило, которое форма не покажет, не открывается.
fn open_editor(app: &mut App, index: Option<usize>) -> Task<Message> {
    let draft = match index {
        Some(index) => {
            let rules = &app.state().config.routing.rules;
            rules.get(index).and_then(|found| rule::load(index, found))
        }
        None => Some(rule::Draft::default()),
    };
    let Some(draft) = draft else {
        return Task::none();
    };

    let split = &mut app.state_mut().split_tunnel;
    split.editor = Some(draft);
    split.app_search.clear();
    split.pick_error = None;
    request_processes()
}

/// Показывает окно выбора файла; второе поверх первого не открывается.
fn pick(app: &mut App) -> Task<Message> {
    let split = &mut app.state_mut().split_tunnel;
    if split.picking {
        return Task::none();
    }
    split.picking = true;
    split.pick_error = None;

    Task::perform(pick_program(), |picked| {
        Message::SplitTunnel(SplitTunnelMessage::AppPicked(picked))
    })
}

fn picked_file(app: &mut App, picked: Result<Option<String>, String>) -> Task<Message> {
    let split = &mut app.state_mut().split_tunnel;
    split.picking = false;

    match picked {
        // Закрыл окно без выбора — не ошибка.
        Ok(None) => {}
        Ok(Some(path)) => {
            // Окно правила могли закрыть, пока искали файл.
            if let Some(draft) = split.editor.as_mut() {
                draft.toggle_process(&path, true);
            }
            // Поиск спрятал бы выбранное: кнопку жмут, когда он ничего не нашёл.
            split.app_search.clear();
        }
        Err(reason) => split.pick_error = Some(reason),
    }
    Task::none()
}

/// Новая группа встаёт в конец, правленая — на своё место с прежними
/// идентификатором, включённостью и приоритетом.
fn save_draft(app: &mut App) -> Task<Message> {
    let state = app.state();
    let Some(draft) = state.split_tunnel.editor.as_ref() else {
        return Task::none();
    };
    let rules = &state.config.routing.rules;
    let previous = draft.index.and_then(|index| rules.get(index));
    let id = previous.map_or_else(|| rule::unique_id(rules), |found| found.id.clone());

    // Без условий правило совпало бы со всем подряд.
    let Some(mut built) = draft.build(id) else {
        return Task::none();
    };
    if let Some(previous) = previous {
        built.enabled = previous.enabled;
        built.priority = previous.priority;
    }
    let place = previous.and(draft.index);

    let rules = &mut app.state_mut().config.routing.rules;
    match place {
        Some(index) => rules[index] = built,
        None => rules.push(built),
    }
    // Окно закрывается сразу, иначе черновик выглядит ещё не сохранённым.
    app.state_mut().split_tunnel.editor = None;
    app.state_mut().dirty = true;
    Task::none()
}

/// Меняет местами два правила; приоритет остаётся за местом, иначе перестановка
/// не изменила бы порядок проверки.
fn move_rule(rules: &mut [RuleConfig], from: usize, to: usize) -> bool {
    if from == to || from >= rules.len() || to >= rules.len() {
        return false;
    }
    let (first, second) = (rules[from].priority, rules[to].priority);
    rules.swap(from, to);
    rules[from].priority = first;
    rules[to].priority = second;
    true
}

/// Спрашивает список запущенных приложений.
pub fn request_processes() -> Task<Message> {
    request(Request::ListProcesses)
}

/// Просит систему показать окно выбора файла в отдельном потоке (оно держит поток).
///
/// Путь нормализуется как в списке службы, иначе один файл выглядел бы двумя
/// приложениями.
async fn pick_program() -> Result<Option<String>, String> {
    // Подписи переведены здесь: платформенный слой языка не знает.
    let title = crate::i18n::s().pick_app_title;
    let filter = crate::i18n::s().programs;

    let picked =
        tokio::task::spawn_blocking(move || penguin_platform::dialog::pick_program(title, filter))
            .await;

    match picked {
        Ok(Ok(path)) => Ok(path.map(|path| penguin_core::path::normalize(&path.to_string_lossy()))),
        Ok(Err(err)) => Err(failure(err)),
        Err(err) => Err(failure(err)),
    }
}

fn failure(reason: impl std::fmt::Display) -> String {
    format!("{}: {reason}", crate::i18n::s().pick_failed)
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::routing::TunnelMode;
    use serde_json::json;

    use super::*;

    fn app_with_rules(rules: serde_json::Value) -> App {
        let (mut app, _task) = App::new(uikit::ThemeType::Dark, false);
        app.state_mut().config.routing.rules =
            serde_json::from_value::<Vec<RuleConfig>>(rules).expect("правила разбираются");
        app
    }

    #[test]
    fn toggling_a_rule_marks_the_config_dirty() {
        let mut app = app_with_rules(json!([
            { "id": "r1", "when": { "dest_port": [443] }, "action": "direct" }
        ]));
        assert!(!app.state().dirty);

        let _ = handle(&mut app, SplitTunnelMessage::RuleToggled(0, false));

        assert!(app.state().dirty);
        assert!(!app.state().config.routing.rules[0].enabled);
    }

    #[test]
    fn removing_out_of_range_does_nothing() {
        let mut app = app_with_rules(json!([
            { "id": "r1", "when": { "dest_port": [443] }, "action": "direct" }
        ]));
        let _ = handle(&mut app, SplitTunnelMessage::RuleRemoved(99));

        assert_eq!(app.state().config.routing.rules.len(), 1);
        assert!(!app.state().dirty, "ничего не изменилось — и правок нет");
    }

    #[test]
    fn removing_a_rule_works() {
        let mut app = app_with_rules(json!([
            { "id": "r1", "when": { "dest_port": [443] }, "action": "direct" },
            { "id": "r2", "when": { "dest_port": [80] }, "action": "block" }
        ]));
        let _ = handle(&mut app, SplitTunnelMessage::RuleRemoved(0));

        assert_eq!(app.state().config.routing.rules.len(), 1);
        assert_eq!(app.state().config.routing.rules[0].id, "r2");
    }

    #[test]
    fn mode_change_reaches_the_config() {
        let mut app = app_with_rules(json!([]));
        let _ = handle(
            &mut app,
            SplitTunnelMessage::ModeSelected(TunnelMode::Block),
        );
        assert_eq!(app.state().config.routing.mode, TunnelMode::Block);
        assert!(app.state().dirty);
    }

    #[test]
    fn moving_a_rule_changes_the_order_of_checking() {
        let mut app = app_with_rules(json!([
            { "id": "r1", "priority": -100, "when": { "dest_port": [443] }, "action": "direct" },
            { "id": "r2", "when": { "dest_port": [80] }, "action": "block" }
        ]));
        let _ = handle(&mut app, SplitTunnelMessage::RuleMoved(1, 0));

        let rules = &app.state().config.routing.rules;
        assert_eq!(rules[0].id, "r2");
        assert_eq!(rules[0].priority, -100, "приоритет ушёл вместе с правилом");
        assert!(app.state().dirty);
    }

    #[test]
    fn moving_past_the_edge_does_nothing() {
        let mut app = app_with_rules(json!([
            { "id": "r1", "when": { "dest_port": [443] }, "action": "direct" }
        ]));
        let _ = handle(&mut app, SplitTunnelMessage::RuleMoved(0, 1));
        assert!(!app.state().dirty);
    }

    #[test]
    fn editing_a_group_keeps_its_place_and_identity() {
        let mut app = app_with_rules(json!([
            { "id": "r1", "when": { "dest_port": [443] }, "action": "direct" },
            { "id": "keep", "enabled": false, "when": { "domain_suffix": ["a.com"] }, "action": "block" }
        ]));
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened(Some(1)));
        let _ = handle(
            &mut app,
            SplitTunnelMessage::DraftHostsChanged("b.com".to_owned()),
        );
        let _ = handle(&mut app, SplitTunnelMessage::DraftSaved);

        let rules = &app.state().config.routing.rules;
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1].id, "keep");
        assert!(!rules[1].enabled, "правка включила выключенное");
        assert_eq!(
            rules[1].when,
            penguin_config::schema::rule::Condition::Leaf(
                penguin_config::schema::rule::Leaf::DomainSuffix(vec!["b.com".to_owned()])
            )
        );
    }

    #[test]
    fn a_handwritten_rule_does_not_open() {
        let mut app = app_with_rules(json!([
            { "id": "r1", "when": { "not": { "dest_port": [443] } }, "action": "direct" }
        ]));
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened(Some(0)));
        assert!(app.state().split_tunnel.editor.is_none());
    }

    #[test]
    fn empty_probe_does_not_ask_the_daemon() {
        let mut app = app_with_rules(json!([]));
        let _ = handle(
            &mut app,
            SplitTunnelMessage::ProbeDestinationChanged("   ".to_owned()),
        );
        let _ = handle(&mut app, SplitTunnelMessage::ProbeRequested);
        assert!(app.state().split_tunnel.probe_result.is_none());
    }

    #[test]
    fn adding_a_rule_puts_it_in_the_config_and_clears_the_draft() {
        let mut app = app_with_rules(json!([]));

        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened(None));
        let _ = handle(
            &mut app,
            SplitTunnelMessage::DraftNameChanged("Игры".to_owned()),
        );
        let _ = handle(
            &mut app,
            SplitTunnelMessage::AppToggled("c:/games/steam.exe".to_owned(), true),
        );
        let _ = handle(&mut app, SplitTunnelMessage::DraftSaved);

        assert_eq!(app.state().config.routing.rules.len(), 1);
        assert_eq!(app.state().config.routing.rules[0].name, "Игры");
        assert!(
            app.state().split_tunnel.editor.is_none(),
            "окно осталось открытым с добавленным правилом"
        );
        assert!(app.state().dirty);
    }

    #[test]
    fn an_empty_draft_adds_nothing() {
        let mut app = app_with_rules(json!([]));
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened(None));
        let _ = handle(
            &mut app,
            SplitTunnelMessage::DraftNameChanged("Пусто".to_owned()),
        );
        let _ = handle(&mut app, SplitTunnelMessage::DraftSaved);

        assert!(app.state().config.routing.rules.is_empty());
        assert!(!app.state().dirty, "ничего не добавилось — и правок нет");
    }

    #[test]
    fn new_rules_never_collide_with_existing_identifiers() {
        let mut app = app_with_rules(json!([
            { "id": "rule-1", "when": { "dest_port": [443] }, "action": "direct" }
        ]));

        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened(None));
        let _ = handle(
            &mut app,
            SplitTunnelMessage::DraftHostsChanged("example.com".to_owned()),
        );
        let _ = handle(&mut app, SplitTunnelMessage::DraftSaved);

        let ids: Vec<&str> = app
            .state()
            .config
            .routing
            .rules
            .iter()
            .map(|rule| rule.id.as_str())
            .collect();
        assert_eq!(ids, ["rule-1", "rule-2"]);
    }

    #[test]
    fn unique_id_skips_taken_ones() {
        let rules: Vec<RuleConfig> = serde_json::from_value(json!([
            { "id": "rule-1", "when": { "dest_port": [1] }, "action": "direct" },
            { "id": "rule-3", "when": { "dest_port": [3] }, "action": "direct" }
        ]))
        .expect("правила разбираются");

        assert_eq!(rule::unique_id(&rules), "rule-2");
        assert_eq!(rule::unique_id(&[]), "rule-1");
    }

    #[test]
    fn a_chosen_file_becomes_a_condition() {
        let mut app = app_with_rules(json!([]));
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened(None));
        let _ = handle(
            &mut app,
            SplitTunnelMessage::AppSearchChanged("doom".to_owned()),
        );

        let _ = handle(
            &mut app,
            SplitTunnelMessage::AppPicked(Ok(Some("c:/games/doom/doom.exe".to_owned()))),
        );

        let draft = app
            .state()
            .split_tunnel
            .editor
            .as_ref()
            .expect("окно открыто");
        assert_eq!(draft.processes, ["c:/games/doom/doom.exe"]);
        assert!(
            app.state().split_tunnel.app_search.is_empty(),
            "отбор по строке поиска спрятал бы только что выбранное"
        );
    }

    #[test]
    fn a_closed_window_adds_nothing() {
        let mut app = app_with_rules(json!([]));
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened(None));
        let _ = handle(&mut app, SplitTunnelMessage::AppPicked(Ok(None)));

        let draft = app
            .state()
            .split_tunnel
            .editor
            .as_ref()
            .expect("окно открыто");
        assert!(draft.processes.is_empty());
        assert!(app.state().split_tunnel.pick_error.is_none());
    }

    #[test]
    fn a_window_that_did_not_open_is_reported() {
        let mut app = app_with_rules(json!([]));
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened(None));
        let _ = handle(
            &mut app,
            SplitTunnelMessage::AppPicked(Err("нечем показать".to_owned())),
        );

        assert_eq!(
            app.state().split_tunnel.pick_error.as_deref(),
            Some("нечем показать")
        );
        assert!(!app.state().split_tunnel.picking, "окна уже нет");
    }

    #[test]
    fn only_one_window_at_a_time() {
        let mut app = app_with_rules(json!([]));
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened(None));
        app.state_mut().split_tunnel.picking = true;
        app.state_mut().split_tunnel.pick_error = Some("прошлая беда".to_owned());

        let _ = handle(&mut app, SplitTunnelMessage::AppPickRequested);

        assert_eq!(
            app.state().split_tunnel.pick_error.as_deref(),
            Some("прошлая беда"),
            "нажатие, которого не было, стёрло состояние"
        );
    }

    #[test]
    fn a_new_window_forgets_the_previous_complaint() {
        let mut app = app_with_rules(json!([]));
        app.state_mut().split_tunnel.pick_error = Some("прошлая беда".to_owned());
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened(None));

        assert!(app.state().split_tunnel.pick_error.is_none());
    }

    #[test]
    fn saving_clears_the_dirty_flag() {
        let mut app = app_with_rules(json!([]));
        app.state_mut().dirty = true;
        let _ = handle(&mut app, SplitTunnelMessage::Save);
        assert!(!app.state().dirty);
    }
}
