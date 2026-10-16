//! Окно «Правило для соединения»: что ловить, в какую группу и куда.
//!
//! Сверху — соединение и нынешнее решение, под чертой — сетка: подписи одной
//! колонкой слева, выбор справа, по строке на вопрос; под второй чертой —
//! ответ. Группа стоит перед «куда»: у существующей группы действие своё и
//! показано словом, выбирают его только новой.

use iced::theme::Palette;
use iced::widget::{Space, text};
use iced::{Alignment, Element, Length};
use uikit::layout::{Flex, gap};
use uikit::tokens::type_scale;
use uikit::widgets::{ButtonVariant, Checkbox, Modal, Select, modal};

use crate::app::message::{LogsMessage, Message};
use crate::app::state::State;
use crate::forms::flow::{FlowRule, widths};
use crate::forms::rule::Action;
use crate::screens::rules::editor::shorten;
use crate::screens::table;
use crate::ui;

/// Ширина окна — как у окна группы.
const WIDTH: f32 = 620.0;

/// Ширина колонки подписей: «ПРИЛОЖЕНИЕ» целиком и воздух до выбора.
const LABEL_WIDTH: f32 = 120.0;

/// Наибольшая длина пути приложения в знаках.
const PATH_WIDTH: usize = 56;

/// Отступ пути под именем приложения: флажок кита (16) и зазор до подписи (8).
const CHECK_INDENT: f32 = 24.0;

/// Собирает окно.
pub fn view<'a>(state: &'a State, window: &'a FlowRule) -> Element<'a, Message> {
    let strings = crate::i18n::s();
    let palette = &state.palette;
    let rules = &state.config.routing.rules;
    let groups = window.groups(rules);

    let action = match window
        .target
        .and_then(|target| groups.iter().find(|(at, _, _)| *at == target))
    {
        // У существующей группы действие своё.
        Some((_, _, action)) => ui::muted(palette, action.label(), type_scale::BODY),
        None => actions(window.action),
    };

    let grid = Flex::col()
        .push_auto(field(palette, strings.catch_address, address(window)))
        .push_auto(field(palette, strings.catch_app, app(palette, window)))
        .push_auto(field(palette, strings.into_group, target(window, &groups)))
        .push_auto(field(palette, strings.action, action))
        .gap(gap::SM)
        .build();

    // Зазоры скромные: окно приложения в 600 точек, и выросшая панель сминала бы
    // кнопки, как когда-то окно группы.
    let form = Flex::col()
        .push_auto(connection(state, window))
        .push_auto(table::divider(palette))
        .push_auto(grid)
        .push_auto(table::divider(palette))
        .push_auto(answer(window))
        .gap(gap::MD)
        .build();

    Modal::new(form)
        .title(strings.flow_rule)
        .max_width(WIDTH)
        .on_close(Message::Logs(LogsMessage::RuleClosed))
        .on_backdrop(Message::Logs(LogsMessage::RuleClosed))
        .build()
        .into()
}

/// Соединение и нынешнее решение: что именно меняют.
fn connection<'a>(state: &'a State, window: &'a FlowRule) -> Element<'a, Message> {
    let strings = crate::i18n::s();
    let flow = &window.flow;
    let who = flow.process.as_deref().unwrap_or("?");
    let reason = flow
        .rule
        .as_ref()
        .and_then(|id| {
            state
                .config
                .routing
                .rules
                .iter()
                .find(|rule| &rule.id == id)
        })
        .map_or(strings.rest, |rule| rule.name.as_str());

    // Без стрелки: её нет в шрифте, и запасной знак налезал на адрес.
    let route = Flex::row()
        .push_auto(text(who).size(type_scale::BODY))
        .push_auto(ui::muted(&state.palette, &flow.target, type_scale::BODY))
        .gap(gap::LG)
        .align(Alignment::Center)
        .build();

    Flex::col()
        .push_auto(route)
        .push_auto(ui::faint(
            &state.palette,
            format!(
                "{} {} · {reason}",
                strings.decided_now,
                flow.action().label()
            ),
            type_scale::MICRO,
        ))
        .gap(gap::XS)
        .build()
}

/// Строка сетки: подпись в колонке слева, выбор справа.
fn field<'a>(
    palette: &Palette,
    label: &'a str,
    body: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    let label = iced::widget::container(ui::faint(palette, label, type_scale::MICRO))
        .width(Length::Fixed(LABEL_WIDTH));
    Flex::row()
        .push_auto(label)
        .push(body)
        .align(Alignment::Center)
        .build()
}

/// Адрес: флажок с самим адресом; у домена — ещё выбор ширины.
fn address(window: &FlowRule) -> Element<'_, Message> {
    let options = widths(window.flow.host());
    let check = |label: String| {
        Checkbox::new(label, window.catch_host)
            .on_toggle(|on| Message::Logs(LogsMessage::CatchHost(on)))
    };
    if options.len() == 1 {
        return check(window.flow.host().to_owned()).into();
    }

    let chosen = options[window.width.min(options.len() - 1)].clone();
    let all = options.clone();
    let width = Select::new(options, Some(chosen), move |picked: String| {
        let at = all
            .iter()
            .position(|option| *option == picked)
            .unwrap_or_default();
        Message::Logs(LogsMessage::WidthSelected(at))
    })
    .view();

    Flex::row()
        .push_auto(check(String::new()))
        .push(width)
        .gap(gap::SM)
        .align(Alignment::Center)
        .build()
}

/// Приложение: флажок с именем, путь — под ним, с отступом флажка.
fn app<'a>(palette: &Palette, window: &'a FlowRule) -> Element<'a, Message> {
    let name = window
        .flow
        .process
        .clone()
        .unwrap_or_else(|| "?".to_owned());
    let (check, path) = match window.app() {
        Some(path) => (
            Checkbox::new(name, window.catch_app)
                .on_toggle(|on| Message::Logs(LogsMessage::CatchApp(on))),
            shorten(path, PATH_WIDTH),
        ),
        // Без пути правило приложение не узнает — флажок не нажимается.
        None => (
            Checkbox::new(name, false),
            crate::i18n::s().path_unknown.to_owned(),
        ),
    };

    Flex::col()
        .push_auto(check)
        .push_auto(
            Flex::row()
                .push_auto(Space::new().width(Length::Fixed(CHECK_INDENT)))
                .push_auto(ui::faint(palette, path, type_scale::MICRO))
                .build(),
        )
        .gap(gap::XS)
        .build()
}

/// Пункт списка групп: номер в наборе (`None` — новая) и подпись.
#[derive(Debug, Clone, PartialEq)]
struct Choice {
    target: Option<usize>,
    label: String,
}

impl std::fmt::Display for Choice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}

/// Новая группа или одна из тех, что добавленное расширит.
fn target<'a>(window: &FlowRule, groups: &[(usize, &str, Action)]) -> Element<'a, Message> {
    let strings = crate::i18n::s();
    let fresh = Choice {
        target: None,
        label: strings.new_group.to_owned(),
    };
    let choices: Vec<Choice> = std::iter::once(fresh)
        .chain(groups.iter().map(|(index, name, action)| Choice {
            target: Some(*index),
            label: format!("{name} · {}", action.label()),
        }))
        .collect();
    let chosen = choices
        .iter()
        .find(|choice| choice.target == window.target)
        .cloned();

    Select::new(choices, chosen, |picked: Choice| {
        Message::Logs(LogsMessage::TargetSelected(picked.target))
    })
    .view()
}

/// Куда отправить: три кнопки, выбранная — акцентом.
fn actions<'a>(current: Action) -> Element<'a, Message> {
    let mut row = Flex::row();
    for action in Action::ALL {
        let variant = if action == current {
            ButtonVariant::Primary
        } else {
            ButtonVariant::Secondary
        };
        row = row.push_auto(
            ui::button(variant, action.label())
                .on_press(Message::Logs(LogsMessage::ActionSelected(action))),
        );
    }
    row.gap(gap::SM).build()
}

/// Ответ окна; ловить нечего — кнопка не нажимается.
fn answer<'a>(window: &FlowRule) -> Element<'a, Message> {
    let mut add = ui::button(ButtonVariant::Primary, crate::i18n::s().add);
    if !window.is_empty() {
        add = add.on_press(Message::Logs(LogsMessage::RuleSaved));
    }
    Flex::row()
        .push(ui::spring())
        .push_auto(modal::line(">"))
        .push_auto(add)
        .gap(gap::SM)
        .align(Alignment::Center)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::flow::Flow;

    fn window(path: Option<&str>) -> FlowRule {
        FlowRule::new(Flow {
            target: "www.tm.trafficmanager.net:443".to_owned(),
            process: Some("CloudMounter".to_owned()),
            process_path: path.map(str::to_owned),
            decision: "proxy[hysteria]".to_owned(),
            rule: None,
        })
    }

    #[test]
    fn renders_with_and_without_a_path() {
        let state = State::default();
        let _ = view(
            &state,
            &window(Some(
                "/Applications/CloudMounter.app/Contents/MacOS/CloudMounter",
            )),
        );
        let _ = view(&state, &window(None));
    }

    #[test]
    fn renders_for_an_existing_group() {
        let mut state = State::default();
        state.config.routing.rules = serde_json::from_value(serde_json::json!([
            { "id": "r1", "name": "Облака", "when": { "domain_suffix": ["a.example"] }, "action": "direct" }
        ]))
        .expect("правила разбираются");
        let mut window = window(None);
        window.target = Some(0);
        let _ = view(&state, &window);
    }
}
