//! Правка правил раздельного тоннелирования.
//!
//! Правки копятся в окне и уезжают демону только по «Сохранить»: иначе каждый
//! щелчок перезаписывал бы файл и пересобирал набор.

use iced::Task;
use penguin_config::export::{Exported, to_surge};
use penguin_config::import::{Imported, parse_surge};
use penguin_config::schema::rule::RuleConfig;
use penguin_ipc::schema::{LogLevel, Request};

use crate::app::App;
use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::update::{request, save_rules};
use crate::forms::rule;

/// Имя файла, предлагаемое окном сохранения.
const EXPORT_FILE_NAME: &str = "penguin-rules.conf";

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
        SplitTunnelMessage::DraftSectionSelected(section) => {
            let split = &mut app.state_mut().split_tunnel;
            split.section = section;
            split.entry.clear();
            Task::none()
        }
        SplitTunnelMessage::DraftEntryChanged(value) => {
            app.state_mut().split_tunnel.entry = value;
            Task::none()
        }
        SplitTunnelMessage::DraftEntrySubmitted => {
            let split = &mut app.state_mut().split_tunnel;
            if let Some(draft) = split.editor.as_mut() {
                // Непонятое остаётся в поле: его поправят, а не наберут заново.
                split.entry = draft.add(&split.entry);
            }
            Task::none()
        }
        SplitTunnelMessage::DraftValueRemoved(value) => {
            if let Some(draft) = app.state_mut().split_tunnel.editor.as_mut() {
                draft.remove(&value);
            }
            Task::none()
        }
        SplitTunnelMessage::DraftActionSelected(action) => {
            if let Some(draft) = app.state_mut().split_tunnel.editor.as_mut() {
                draft.action = action;
            }
            Task::none()
        }
        SplitTunnelMessage::DraftNetworkSelected(network) => {
            if let Some(draft) = app.state_mut().split_tunnel.editor.as_mut() {
                draft.network = network;
            }
            Task::none()
        }
        SplitTunnelMessage::DraftSaved => save_draft(app),
        SplitTunnelMessage::GeoIpSent(result) => {
            if let Err(reason) = result {
                // Повторится со следующим сохранением правил.
                let state = app.state_mut();
                state.split_tunnel.geoip_sent = false;
                state.connection.push_log(
                    LogLevel::Error,
                    format!("{}: {reason}", crate::i18n::s().geoip_not_sent),
                );
            }
            Task::none()
        }
        SplitTunnelMessage::ImportRequested => import(app),
        SplitTunnelMessage::Imported(result) => imported(app, result),
        SplitTunnelMessage::ExportRequested => export(app),
        SplitTunnelMessage::Exported(result) => {
            app.state_mut().split_tunnel.picking = false;
            // Закрыл окно без выбора — не ошибка.
            if let Ok(Some(report)) | Err(report) = result {
                app.state_mut().split_tunnel.import_report = Some(report);
            }
            Task::none()
        }
        SplitTunnelMessage::Save => {
            app.state_mut().split_tunnel.import_report = None;
            save_rules(app)
        }
    }
}

/// Передаёт службе базу GeoIP, если правилам она нужна; раз за запуск.
pub fn send_geoip(app: &mut App) -> Task<Message> {
    let state = app.state_mut();
    if state.split_tunnel.geoip_sent || !crate::geoip::wanted(&state.config.routing.rules) {
        return Task::none();
    }
    state.split_tunnel.geoip_sent = true;
    Task::perform(crate::geoip::send_to_service(), |result| {
        Message::SplitTunnel(SplitTunnelMessage::GeoIpSent(result))
    })
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

    // Открывается то, что в группе есть: правят обычно его.
    let section = rule::Section::ALL
        .into_iter()
        .find(|section| !draft.values(*section).is_empty())
        .unwrap_or_default();

    let split = &mut app.state_mut().split_tunnel;
    split.editor = Some(draft);
    split.section = section;
    split.app_search.clear();
    split.entry.clear();
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

/// Ставит группу из окна правки в набор; сохраняет только «Сохранить».
fn save_draft(app: &mut App) -> Task<Message> {
    let Some(draft) = app.state().split_tunnel.editor.clone() else {
        return Task::none();
    };
    if store_draft(app, &draft) {
        // Окно закрывается сразу, иначе черновик выглядит ещё не сохранённым.
        app.state_mut().split_tunnel.editor = None;
    }
    Task::none()
}

/// Ставит группу в набор: новую — в конец, правленую — на своё место с прежними
/// идентификатором, включённостью и приоритетом. `false` — условий нет, а
/// такое правило совпало бы со всем подряд.
pub fn store_draft(app: &mut App, draft: &rule::Draft) -> bool {
    let rules = &app.state().config.routing.rules;
    let previous = draft.index.and_then(|index| rules.get(index));
    let id = previous.map_or_else(|| rule::unique_id(rules), |found| found.id.clone());

    let Some(mut built) = draft.build(id) else {
        return false;
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
    app.state_mut().dirty = true;
    true
}

/// Показывает окно выбора списка; окно выбора одно на экран.
fn import(app: &mut App) -> Task<Message> {
    let split = &mut app.state_mut().split_tunnel;
    if split.picking {
        return Task::none();
    }
    split.picking = true;
    split.import_report = None;

    Task::perform(read_rule_list(), |read| {
        Message::SplitTunnel(SplitTunnelMessage::Imported(read))
    })
}

fn imported(app: &mut App, read: Result<Option<Imported>, String>) -> Task<Message> {
    app.state_mut().split_tunnel.picking = false;
    let report = match read {
        // Закрыл окно без выбора — не ошибка.
        Ok(None) => return Task::none(),
        Ok(Some(list)) => apply_import(app, list),
        Err(reason) => reason,
    };
    app.state_mut().split_tunnel.import_report = Some(report);
    Task::none()
}

/// Дописывает группы в конец набора и берёт «всё остальное» из `FINAL`; итог —
/// строкой для человека. Сохраняет, как и правка, только «Сохранить».
fn apply_import(app: &mut App, list: Imported) -> String {
    let strings = crate::i18n::s();
    if list.rules.is_empty() && list.mode.is_none() {
        return strings.import_empty.to_owned();
    }

    let added = list.rules.len();
    let routing = &mut app.state_mut().config.routing;
    for mut imported in list.rules {
        imported.id = rule::unique_id(&routing.rules);
        if imported.name.is_empty() {
            strings.unnamed_rule.clone_into(&mut imported.name);
        }
        routing.rules.push(imported);
    }
    if let Some(mode) = list.mode {
        routing.mode = mode;
    }
    app.state_mut().dirty = true;

    let mut report = format!("{}: {added}", strings.imported_groups);
    if !list.skipped.is_empty() {
        report.push_str(&format!(
            " · {}: {}",
            strings.skipped_lines,
            list.skipped.len()
        ));
    }
    report
}

/// Выгружает набор, как он виден в окне, вместе с несохранёнными правками.
fn export(app: &mut App) -> Task<Message> {
    let split = &mut app.state_mut().split_tunnel;
    if split.picking {
        return Task::none();
    }
    split.picking = true;
    split.import_report = None;

    let routing = &app.state().config.routing;
    let exported = to_surge(&routing.rules, routing.mode);
    Task::perform(write_rule_list(exported), |written| {
        Message::SplitTunnel(SplitTunnelMessage::Exported(written))
    })
}

fn export_report(exported: &Exported) -> String {
    let strings = crate::i18n::s();
    let mut report = format!("{}: {}", strings.exported_groups, exported.written);
    if !exported.skipped.is_empty() {
        report.push_str(&format!(
            " · {}: {}",
            strings.skipped_groups,
            exported.skipped.len()
        ));
    }
    report
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

/// Спрашивает файл и читает его в отдельном потоке: окно держит поток, чтение — тоже.
async fn read_rule_list() -> Result<Option<Imported>, String> {
    let title = crate::i18n::s().import_title;
    let filter = crate::i18n::s().rule_lists;
    let unreadable = crate::i18n::s().import_failed;

    let read = tokio::task::spawn_blocking(move || {
        let Some(path) =
            penguin_platform::dialog::pick_rule_list(title, filter).map_err(failure)?
        else {
            return Ok(None);
        };
        let text = std::fs::read_to_string(&path).map_err(|err| format!("{unreadable}: {err}"))?;
        Ok(Some(parse_surge(&text)))
    })
    .await;

    read.unwrap_or_else(|err| Err(failure(err)))
}

/// Спрашивает, куда сохранить, и пишет файл в отдельном потоке, как и чтение.
async fn write_rule_list(exported: Exported) -> Result<Option<String>, String> {
    let title = crate::i18n::s().export_title;
    let filter = crate::i18n::s().rule_lists;
    let unwritable = crate::i18n::s().export_failed;
    let report = export_report(&exported);

    let written = tokio::task::spawn_blocking(move || {
        let Some(path) = penguin_platform::dialog::save_rule_list(title, filter, EXPORT_FILE_NAME)
            .map_err(failure)?
        else {
            return Ok(None);
        };
        std::fs::write(&path, exported.text).map_err(|err| format!("{unwritable}: {err}"))?;
        Ok(Some(report))
    })
    .await;

    written.unwrap_or_else(|err| Err(failure(err)))
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
    fn an_imported_list_joins_the_end_of_the_set() {
        let mut app = app_with_rules(json!([
            { "id": "rule-1", "when": { "dest_port": [443] }, "action": "direct" }
        ]));
        let list = parse_surge(
            "[Rule]\nDOMAIN-SUFFIX,a.example,DIRECT\n# Почта\nDOMAIN,b.example,PROXY\n\
             USER-AGENT,Line*,PROXY\nFINAL,REJECT",
        );
        let _ = handle(&mut app, SplitTunnelMessage::Imported(Ok(Some(list))));

        let state = app.state();
        let ids: Vec<&str> = state
            .config
            .routing
            .rules
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(ids, ["rule-1", "rule-2", "rule-3"]);
        assert_eq!(
            state.config.routing.rules[1].name,
            crate::i18n::s().unnamed_rule
        );
        assert_eq!(state.config.routing.rules[2].name, "Почта");
        assert_eq!(state.config.routing.mode, TunnelMode::Block);
        assert!(state.dirty);
        let report = state
            .split_tunnel
            .import_report
            .as_deref()
            .unwrap_or_default();
        assert!(report.contains(": 2") && report.contains(": 1"), "{report}");
    }

    #[test]
    fn an_empty_list_changes_nothing() {
        let mut app = app_with_rules(json!([]));
        let list = parse_surge("[Rule]\nIP-ASN,1,DIRECT");
        let _ = handle(&mut app, SplitTunnelMessage::Imported(Ok(Some(list))));

        assert!(app.state().config.routing.rules.is_empty());
        assert!(!app.state().dirty);
        assert_eq!(
            app.state().split_tunnel.import_report.as_deref(),
            Some(crate::i18n::s().import_empty)
        );
    }

    #[test]
    fn the_export_report_names_partial_groups() {
        let rules = serde_json::from_value::<Vec<RuleConfig>>(json!([
            { "id": "r1", "when": { "domain": ["a.example"] }, "action": "direct" },
            { "id": "r2", "when": { "geo_ip": ["RU"] }, "action": "direct" }
        ]))
        .expect("правила разбираются");
        let report = export_report(&to_surge(&rules, TunnelMode::Tunnel));
        let strings = crate::i18n::s();
        assert_eq!(
            report,
            format!(
                "{}: 1 · {}: 1",
                strings.exported_groups, strings.skipped_groups
            )
        );
    }

    #[test]
    fn a_closed_save_dialog_is_not_a_failure() {
        let mut app = app_with_rules(json!([]));
        app.state_mut().split_tunnel.picking = true;
        let _ = handle(&mut app, SplitTunnelMessage::Exported(Ok(None)));

        assert!(!app.state().split_tunnel.picking);
        assert!(app.state().split_tunnel.import_report.is_none());
    }

    #[test]
    fn a_closed_dialog_is_not_a_failure() {
        let mut app = app_with_rules(json!([]));
        app.state_mut().split_tunnel.picking = true;
        let _ = handle(&mut app, SplitTunnelMessage::Imported(Ok(None)));

        assert!(!app.state().split_tunnel.picking);
        assert!(app.state().split_tunnel.import_report.is_none());
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
        assert_eq!(
            app.state().split_tunnel.section,
            rule::Section::Hosts,
            "окно открылось на том, что в группе есть"
        );
        let _ = handle(
            &mut app,
            SplitTunnelMessage::DraftValueRemoved("a.com".to_owned()),
        );
        let _ = handle(
            &mut app,
            SplitTunnelMessage::DraftEntryChanged("b.com ???".to_owned()),
        );
        let _ = handle(&mut app, SplitTunnelMessage::DraftEntrySubmitted);
        assert_eq!(
            app.state().split_tunnel.entry,
            "???",
            "непонятое осталось в поле"
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
            SplitTunnelMessage::DraftEntryChanged("example.com".to_owned()),
        );
        let _ = handle(&mut app, SplitTunnelMessage::DraftEntrySubmitted);
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
