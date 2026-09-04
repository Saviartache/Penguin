//! Правка правил раздельного тоннелирования.
//!
//! Правки копятся в окне и уезжают демону только по «Сохранить». Причина не в
//! экономии обмена: каждое нажатие в списке из тридцати правил перезаписывало
//! бы файл настроек и пересобирало весь набор — а пользователь в это время
//! ещё думает.

use iced::Task;
use penguin_ipc::schema::Request;

use crate::app::App;
use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::update::{request, save_rules};
use crate::forms::rule;

/// Разбирает экран правил.
pub fn handle(app: &mut App, message: SplitTunnelMessage) -> Task<Message> {
    match message {
        SplitTunnelMessage::ModeSelected(mode) => {
            if let Some(mode) = parse_mode(&mode) {
                app.state_mut().config.routing.mode = mode;
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

        SplitTunnelMessage::ProbeRequested => {
            let state = &app.state().split_tunnel;
            if state.probe_destination.trim().is_empty() {
                return Task::none();
            }

            let process =
                Some(state.probe_process.trim().to_owned()).filter(|value| !value.is_empty());

            request(Request::Explain {
                destination: state.probe_destination.trim().to_owned(),
                process,
                udp: false,
            })
        }

        SplitTunnelMessage::EditorOpened => {
            app.state_mut().split_tunnel.editor = Some(rule::Draft::default());
            // Поиск по приложениям остался бы от прошлого правила, и список в
            // свежем окне оказался бы уже отобранным неизвестно по чему.
            app.state_mut().split_tunnel.app_search.clear();
            // То же и с жалобой окна выбора: к новому правилу она отношения
            // не имеет.
            app.state_mut().split_tunnel.pick_error = None;
            // Список запущенного мог устареть за то время, что окно открыто:
            // спрашиваем заново ровно тогда, когда он понадобился.
            request_processes()
        }

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

        SplitTunnelMessage::AppPickRequested => {
            // Второе окно поверх первого — два ответа на один вопрос, и
            // второй придёт тогда, когда правило уже собрано по первому.
            if app.state().split_tunnel.picking {
                return Task::none();
            }
            app.state_mut().split_tunnel.picking = true;
            // Прошлая беда к этому нажатию отношения не имеет.
            app.state_mut().split_tunnel.pick_error = None;

            Task::perform(pick_program(), |picked| {
                Message::SplitTunnel(SplitTunnelMessage::AppPicked(picked))
            })
        }

        SplitTunnelMessage::AppPicked(picked) => {
            app.state_mut().split_tunnel.picking = false;

            match picked {
                // Человек закрыл окно, ничего не выбрав, и знает об этом сам.
                Ok(None) => {}
                Ok(Some(path)) => {
                    // Окно правила могли закрыть, пока человек искал файл.
                    if let Some(draft) = app.state_mut().split_tunnel.editor.as_mut() {
                        draft.toggle_process(&path, true);
                    }
                    // Отбор по строке поиска спрятал бы только что выбранное:
                    // кнопку нажали как раз потому, что поиск ничего не нашёл.
                    app.state_mut().split_tunnel.app_search.clear();
                }
                Err(reason) => app.state_mut().split_tunnel.pick_error = Some(reason),
            }
            Task::none()
        }

        SplitTunnelMessage::DraftNameChanged(value) => {
            if let Some(draft) = app.state_mut().split_tunnel.editor.as_mut() {
                draft.name = value;
            }
            Task::none()
        }

        SplitTunnelMessage::DraftAddressesChanged(value) => {
            if let Some(draft) = app.state_mut().split_tunnel.editor.as_mut() {
                draft.addresses = value;
            }
            Task::none()
        }

        SplitTunnelMessage::DraftActionSelected(action) => {
            if let Some(draft) = app.state_mut().split_tunnel.editor.as_mut() {
                draft.action = action;
            }
            Task::none()
        }

        SplitTunnelMessage::RuleAdded => {
            let id = rule::unique_id(&app.state().config.routing.rules);
            let new_rule = app
                .state()
                .split_tunnel
                .editor
                .as_ref()
                .and_then(|draft| draft.build(id));
            let Some(new_rule) = new_rule else {
                // Черновик без условий: правило совпадало бы со всем подряд.
                return Task::none();
            };

            app.state_mut().config.routing.rules.push(new_rule);
            // Окно закрывается сразу: оставленный в нём черновик выглядит как
            // ещё не добавленный, и следующее нажатие даёт второе такое же.
            app.state_mut().split_tunnel.editor = None;
            app.state_mut().dirty = true;
            Task::none()
        }

        SplitTunnelMessage::Save => save_rules(app),
    }
}

/// Спрашивает список запущенных приложений.
pub fn request_processes() -> Task<Message> {
    request(Request::ListProcesses)
}

/// Просит систему показать окно выбора файла.
///
/// Окно системное и **держит поток**, пока человек в нём ищет; в потоке
/// отрисовки это остановило бы окно программы, поэтому оно уезжает в отдельный.
///
/// Путь приводится к тому виду, в каком пути приходят от службы. Иначе
/// `C:\Program Files\App\App.exe` из окна выбора и
/// `c:/program files/app/app.exe` из списка запущенного — два разных
/// приложения для набора правил и две одинаковые строки на экране.
async fn pick_program() -> Result<Option<String>, String> {
    // Подписи переведены здесь: платформенный слой языка интерфейса не знает.
    let title = crate::i18n::s().pick_app_title;
    let filter = crate::i18n::s().programs;

    let picked =
        tokio::task::spawn_blocking(move || penguin_platform::dialog::pick_program(title, filter))
            .await;

    match picked {
        Ok(Ok(path)) => Ok(path.map(|path| penguin_core::path::normalize(&path.to_string_lossy()))),
        Ok(Err(err)) => Err(failure(err)),
        // Поток с окном не довёл дело до конца. Для человека это то же самое,
        // что и отказ системы: окно было, ответа нет.
        Err(err) => Err(failure(err)),
    }
}

/// Складывает сообщение о том, что окно выбора не открылось.
fn failure(reason: impl std::fmt::Display) -> String {
    format!("{}: {reason}", crate::i18n::s().pick_failed)
}

/// Разбирает режим из подписи в списке.
///
/// Свободная функция с тестом: подписи видны пользователю и меняются, а
/// значения в файле настроек — нет. Разойтись им нельзя.
pub fn parse_mode(label: &str) -> Option<penguin_config::schema::routing::TunnelMode> {
    use penguin_config::schema::routing::TunnelMode;

    Some(match label {
        "full" => TunnelMode::Full,
        "allowlist" => TunnelMode::Allowlist,
        "blocklist" => TunnelMode::Blocklist,
        "off" => TunnelMode::Off,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::routing::TunnelMode;
    use penguin_config::schema::rule::RuleConfig;
    use serde_json::json;

    use super::*;

    fn app_with_rules(rules: serde_json::Value) -> App {
        let (mut app, _task) = App::new(uikit::ThemeType::Dark);
        app.state_mut().config.routing.rules =
            serde_json::from_value::<Vec<RuleConfig>>(rules).expect("правила разбираются");
        app
    }

    #[test]
    fn every_mode_parses() {
        // Подписи меняются, значения в файле — нет. Разойтись им нельзя.
        for mode in ["full", "allowlist", "blocklist", "off"] {
            assert!(parse_mode(mode).is_some(), "режим `{mode}` не разбирается");
        }
        assert!(parse_mode("нет такого").is_none());
    }

    #[test]
    fn toggling_a_rule_marks_the_config_dirty() {
        // Пока правки не сохранены, кнопка «Сохранить» должна быть заметна.
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
        // Список мог измениться между отрисовкой и щелчком.
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
            SplitTunnelMessage::ModeSelected("allowlist".to_owned()),
        );
        assert_eq!(app.state().config.routing.mode, TunnelMode::Allowlist);
    }

    #[test]
    fn empty_probe_does_not_ask_the_daemon() {
        // Пустой адрес — не запрос, а незаполненная форма.
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
        // Черновик, оставшийся в форме, выглядит как ещё не добавленный, и
        // следующее нажатие даёт второе такое же правило.
        let mut app = app_with_rules(json!([]));

        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened);
        let _ = handle(
            &mut app,
            SplitTunnelMessage::DraftNameChanged("Игры".to_owned()),
        );
        let _ = handle(
            &mut app,
            SplitTunnelMessage::AppToggled("c:/games/steam.exe".to_owned(), true),
        );
        let _ = handle(&mut app, SplitTunnelMessage::RuleAdded);

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
        // Правило без условий совпало бы со всем подряд.
        let mut app = app_with_rules(json!([]));
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened);
        let _ = handle(
            &mut app,
            SplitTunnelMessage::DraftNameChanged("Пусто".to_owned()),
        );
        let _ = handle(&mut app, SplitTunnelMessage::RuleAdded);

        assert!(app.state().config.routing.rules.is_empty());
        assert!(!app.state().dirty, "ничего не добавилось — и правок нет");
    }

    #[test]
    fn new_rules_never_collide_with_existing_identifiers() {
        // Два правила с одним идентификатором — набор, в котором ссылка
        // указывает на два разных правила.
        let mut app = app_with_rules(json!([
            { "id": "rule-1", "when": { "dest_port": [443] }, "action": "direct" }
        ]));

        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened);
        let _ = handle(
            &mut app,
            SplitTunnelMessage::DraftAddressesChanged("example.com".to_owned()),
        );
        let _ = handle(&mut app, SplitTunnelMessage::RuleAdded);

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
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened);
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
        // «Отмена» — не ошибка, и говорить о ней нечего.
        let mut app = app_with_rules(json!([]));
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened);
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
        // Ничего не произошло — и человек решает, что сломана кнопка.
        let mut app = app_with_rules(json!([]));
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened);
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
        // Второе окно поверх первого дало бы два ответа на один вопрос.
        let mut app = app_with_rules(json!([]));
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened);
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
        let _ = handle(&mut app, SplitTunnelMessage::EditorOpened);

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
