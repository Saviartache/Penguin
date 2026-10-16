//! Журнал: левая кнопка копирует запись, правая открывает правило по соединению.
//!
//! Правило из журнала сохраняется сразу: его добавляют, глядя на соединение,
//! и ждут, что следующее такое пойдёт уже по-новому.

use std::time::Duration;

use iced::{Task, mouse};
use penguin_ipc::schema::LogLevel;

use crate::app::App;
use crate::app::message::{LogsMessage, Message};
use crate::app::update::rules::store_draft;
use crate::app::update::save_rules;
use crate::forms::flow::FlowRule;

/// Сколько стоит плашка «скопировано».
const COPIED_FOR: Duration = Duration::from_secs(2);

/// Разбирает экран журнала.
pub fn handle(app: &mut App, message: LogsMessage) -> Task<Message> {
    match message {
        LogsMessage::LinePressed(index, button) => pressed(app, index, button),
        LogsMessage::CopiedShown(number) => {
            let logs = &mut app.state_mut().logs;
            if logs
                .copied
                .as_ref()
                .is_some_and(|(shown, _)| *shown == number)
            {
                logs.copied = None;
            }
            Task::none()
        }
        LogsMessage::CatchHost(on) => edit(app, |rule| rule.catch_host = on),
        LogsMessage::WidthSelected(width) => edit(app, |rule| {
            rule.width = width;
            rule.catch_host = true;
        }),
        LogsMessage::CatchApp(on) => edit(app, |rule| rule.catch_app = on),
        // Действие выбирают только новой группе: у существующей оно своё.
        LogsMessage::ActionSelected(action) => edit(app, |rule| {
            rule.action = action;
            rule.target = None;
        }),
        LogsMessage::TargetSelected(target) => edit(app, |rule| rule.target = target),
        LogsMessage::RuleSaved => save(app),
        LogsMessage::RuleClosed => {
            app.state_mut().logs.rule = None;
            Task::none()
        }
    }
}

/// Правая кнопка — окно правила (только у строки соединения), остальные —
/// копирование: адрес соединения или строка как есть.
fn pressed(app: &mut App, index: usize, button: mouse::Button) -> Task<Message> {
    let state = app.state();
    let Some(line) = state.connection.log.get(index) else {
        return Task::none();
    };

    if button == mouse::Button::Right {
        if let Some(flow) = line.flow.clone() {
            app.state_mut().logs.rule = Some(FlowRule::new(flow));
        }
        return Task::none();
    }

    let text = match &line.flow {
        Some(flow) => flow.host().to_owned(),
        None => state.connection.lines[index].clone(),
    };
    let logs = &mut app.state_mut().logs;
    logs.copies += 1;
    let number = logs.copies;
    logs.copied = Some((number, text.clone()));

    Task::batch([
        iced::clipboard::write(text),
        // Таймер заводится уже в исполнителе: вне его `sleep` паникует.
        Task::perform(async { tokio::time::sleep(COPIED_FOR).await }, move |()| {
            Message::Logs(LogsMessage::CopiedShown(number))
        }),
    ])
}

/// Правит окно; группа, в которую добавленное больше не вписывается, снимается.
fn edit(app: &mut App, change: impl FnOnce(&mut FlowRule)) -> Task<Message> {
    let state = app.state_mut();
    let Some(rule) = state.logs.rule.as_mut() else {
        return Task::none();
    };
    change(rule);
    if let Some(target) = rule.target {
        let fits = rule
            .groups(&state.config.routing.rules)
            .iter()
            .any(|(index, _, _)| *index == target);
        if !fits {
            rule.target = None;
        }
    }
    Task::none()
}

/// Ставит группу в набор и сразу отправляет набор службе.
fn save(app: &mut App) -> Task<Message> {
    let state = app.state();
    let Some(draft) = state
        .logs
        .rule
        .as_ref()
        .and_then(|rule| rule.draft(&state.config.routing.rules))
    else {
        return Task::none();
    };
    if !store_draft(app, &draft) {
        return Task::none();
    }

    let name = draft.name.trim().to_owned();
    let state = app.state_mut();
    state.logs.rule = None;
    state.connection.push_log(
        LogLevel::Info,
        format!("{} «{name}»", crate::i18n::s().added_to_group),
    );
    save_rules(app)
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::rule::RuleConfig;
    use serde_json::json;

    use super::*;
    use crate::forms::flow::Flow;
    use crate::forms::rule::Action;

    fn app_with_flow() -> App {
        let (mut app, _task) = App::new(uikit::ThemeType::Dark, false);
        app.state_mut().config.routing.rules = serde_json::from_value::<Vec<RuleConfig>>(json!([
            { "id": "rule-1", "name": "LAN", "when": { "dest_ip": ["10.0.0.0/8"] }, "action": "direct" }
        ]))
        .expect("правила разбираются");
        let connection = &mut app.state_mut().connection;
        connection.push_log(LogLevel::Error, "служба молчит".to_owned());
        connection.push_flow(Flow {
            target: "192.168.0.131:24800".to_owned(),
            process: Some("synergy-core".to_owned()),
            process_path: Some("/usr/bin/synergy-core".to_owned()),
            decision: "proxy[hysteria]".to_owned(),
            rule: None,
        });
        app
    }

    #[test]
    fn a_left_click_copies_the_address_of_a_connection() {
        let mut app = app_with_flow();
        let _ = handle(&mut app, LogsMessage::LinePressed(1, mouse::Button::Left));
        let (number, text) = app.state().logs.copied.clone().expect("скопировано");
        assert_eq!(text, "192.168.0.131");

        // Чужое ожидание плашку не гасит, своё — гасит.
        let _ = handle(&mut app, LogsMessage::CopiedShown(number + 1));
        assert!(app.state().logs.copied.is_some());
        let _ = handle(&mut app, LogsMessage::CopiedShown(number));
        assert!(app.state().logs.copied.is_none());
    }

    #[test]
    fn a_left_click_on_a_plain_line_copies_it_whole() {
        let mut app = app_with_flow();
        let _ = handle(&mut app, LogsMessage::LinePressed(0, mouse::Button::Left));
        let (_, text) = app.state().logs.copied.clone().expect("скопировано");
        assert!(text.ends_with("служба молчит"), "{text}");
    }

    #[test]
    fn a_right_click_opens_the_rule_only_for_a_connection() {
        let mut app = app_with_flow();
        let _ = handle(&mut app, LogsMessage::LinePressed(0, mouse::Button::Right));
        assert!(app.state().logs.rule.is_none());
        let _ = handle(&mut app, LogsMessage::LinePressed(1, mouse::Button::Right));
        assert!(app.state().logs.rule.is_some());
    }

    #[test]
    fn a_rule_from_the_log_is_saved_at_once() {
        let mut app = app_with_flow();
        let _ = handle(&mut app, LogsMessage::LinePressed(1, mouse::Button::Right));
        let _ = handle(&mut app, LogsMessage::TargetSelected(Some(0)));
        let _ = handle(&mut app, LogsMessage::RuleSaved);

        let state = app.state();
        assert!(state.logs.rule.is_none());
        assert!(!state.dirty, "набор уехал службе сразу");
        assert_eq!(state.config.routing.rules.len(), 1);
        assert_eq!(
            state.saved.routing.rules[0].when,
            crate::forms::rule::Draft {
                hosts: vec!["10.0.0.0/8".to_owned(), "192.168.0.131".to_owned()],
                ..Default::default()
            }
            .build("x")
            .expect("собирается")
            .when
        );
    }

    #[test]
    fn choosing_an_action_means_a_new_group() {
        let mut app = app_with_flow();
        let _ = handle(&mut app, LogsMessage::LinePressed(1, mouse::Button::Right));
        let _ = handle(&mut app, LogsMessage::TargetSelected(Some(0)));
        let _ = handle(&mut app, LogsMessage::ActionSelected(Action::Block));
        let _ = handle(&mut app, LogsMessage::RuleSaved);

        let rules = &app.state().config.routing.rules;
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1].name, "192.168.0.131");
    }

    #[test]
    fn a_group_that_no_longer_fits_is_dropped() {
        let mut app = app_with_flow();
        let _ = handle(&mut app, LogsMessage::LinePressed(1, mouse::Button::Right));
        let _ = handle(&mut app, LogsMessage::TargetSelected(Some(0)));
        let _ = handle(&mut app, LogsMessage::CatchApp(true));
        assert_eq!(
            app.state().logs.rule.as_ref().and_then(|rule| rule.target),
            None
        );
    }
}
