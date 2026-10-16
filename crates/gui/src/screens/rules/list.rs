//! Вкладка правил: режим, кнопки, таблица.
//!
//! Та же таблица ([`crate::screens::table`]), что у серверов: значения сравнивают
//! между строками. Главный столбец — условие (какое соединение правило заберёт),
//! описывается тем же кодом, что и в проверке ([`super::describe`]).
//!
//! Форма и проверка живут в модальных окнах, у вкладки нет своей прокрутки.
//! Выключенное правило приглушено и помечено словом: вычёркивания нет в шрифте,
//! а спрятанное правило ищут и не находят.

use iced::widget::button;
use iced::{Alignment, Element, Length};
use penguin_config::schema::rule::RuleConfig;
use uikit::layout::{Flex, Sizable, Size, gap, px};
use uikit::tokens::ink;
use uikit::widgets::ButtonVariant;

use crate::app::TAB_GAP;
use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::screens::rules::describe::{describe_action, describe_condition};
use crate::screens::rules::mode;
use crate::screens::table::{
    self, BUTTON_HEIGHT, CELL, ROW_GAP, ROW_PADDING, cell, glyphs, lpad, pad,
};
use crate::ui;

/// Ширина столбца имени в знаках; длинное режется, а не двигает условие.
const NAME_WIDTH: usize = 20;

/// Ширина столбца условия — самого широкого.
const CONDITION_WIDTH: usize = 46;

/// Ширина столбца действия: «в тоннель -> office» не должно ломать таблицу.
const ACTION_WIDTH: usize = 20;

/// Ширина кнопки удаления в точках.
const REMOVE_WIDTH: f32 = 76.0;

/// Собирает вкладку целиком.
pub fn view(state: &State) -> Element<'_, Message> {
    Flex::col()
        .w(Size::FILL)
        .h(Size::FILL)
        .push_auto(mode::view(state))
        .push_auto(toolbar(state))
        .push(panel(state))
        .gap(TAB_GAP)
        .build()
}

/// Кнопки над таблицей. «Сохранить» — только при несохранённых правках, у
/// правого края и акцентом: постоянно видимая, она перестаёт что-либо значить.
fn toolbar(state: &State) -> Element<'_, Message> {
    let mut row = Flex::row()
        .push_auto(
            ui::button(ButtonVariant::Primary, crate::i18n::s().add_rule)
                .h(px(BUTTON_HEIGHT))
                .on_press(Message::SplitTunnel(SplitTunnelMessage::EditorOpened)),
        )
        .push_auto(
            ui::button(ButtonVariant::Secondary, crate::i18n::s().probe_rule)
                .h(px(BUTTON_HEIGHT))
                .on_press(Message::SplitTunnel(SplitTunnelMessage::ProbeOpened)),
        )
        .push(ui::spring());

    if state.dirty {
        row = row.push_auto(
            ui::button(ButtonVariant::Primary, crate::i18n::s().save)
                .h(px(BUTTON_HEIGHT))
                .on_press(Message::SplitTunnel(SplitTunnelMessage::Save)),
        );
    }

    row.gap(gap::SM).align(Alignment::Center).build()
}

fn panel(state: &State) -> Element<'_, Message> {
    table::panel(
        &state.palette,
        table::search(
            crate::i18n::s().search,
            &state.split_tunnel.search,
            |value| Message::SplitTunnel(SplitTunnelMessage::SearchChanged(value)),
        ),
        head(state),
        rows(state),
        crate::i18n::s().toggle_hint,
    )
}

/// Шапка таблицы с тем же отступом и местом под «удалить», что у строки.
fn head(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    let dim = ink::level(&state.palette, ink::TERTIARY);

    let titles = columns(
        glyphs(pad(strings.rule, NAME_WIDTH), dim),
        glyphs(pad(strings.condition, CONDITION_WIDTH), dim),
        None,
        glyphs(lpad(strings.action, ACTION_WIDTH), dim),
    );

    Flex::row()
        .w(Size::FILL)
        .push(
            iced::widget::container(titles)
                .padding(ROW_PADDING)
                .width(Length::Fill),
        )
        .push_auto(iced::widget::Space::new().width(Length::Fixed(REMOVE_WIDTH)))
        .gap(gap::NONE)
        .build()
}

/// Прокручиваемое тело таблицы.
fn rows(state: &State) -> Element<'_, Message> {
    let rules = &state.config.routing.rules;
    if rules.is_empty() {
        return table::empty(&state.palette, crate::i18n::s().no_rules);
    }

    // Номер берётся до отбора: он уезжает в сообщение об удалении.
    let shown: Vec<(usize, &RuleConfig)> = rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| found(rule, &state.split_tunnel.search))
        .collect();
    if shown.is_empty() {
        return table::empty(&state.palette, crate::i18n::s().nothing_found);
    }

    let list = Flex::col()
        .w(Size::FILL)
        .extend(
            shown
                .into_iter()
                .map(|(index, rule)| row(state, index, rule)),
        )
        .gap(ROW_GAP)
        .build();

    table::scroll(list)
}

/// Подходит ли правило под поиск: по имени, условию и действию.
fn found(rule: &RuleConfig, query: &str) -> bool {
    if query.trim().is_empty() {
        return true;
    }
    let condition = describe_condition(&rule.when);
    let action = describe_action(&rule.action);

    table::matches(query, &[&rule.name, &rule.id, &condition, &action])
}

/// Строка правила: щелчок включает и выключает, кнопка справа удаляет.
fn row<'a>(state: &'a State, index: usize, rule: &'a RuleConfig) -> Element<'a, Message> {
    let palette = &state.palette;
    let action = describe_action(&rule.action);

    let (name_ink, condition_ink, action_ink) = if rule.enabled {
        (
            palette.text,
            ink::level(palette, ink::SECONDARY),
            ink::level(palette, ink::SECONDARY),
        )
    } else {
        let faint = ink::level(palette, ink::TERTIARY);
        (faint, faint, faint)
    };

    let name = if rule.name.trim().is_empty() {
        rule.id.as_str()
    } else {
        rule.name.as_str()
    };
    let off = (!rule.enabled).then(|| {
        glyphs(
            crate::i18n::s().rule_off,
            ink::level(palette, ink::TERTIARY),
        )
    });

    let cells = columns(
        glyphs(cell(name, NAME_WIDTH), name_ink),
        glyphs(
            cell(&describe_condition(&rule.when), CONDITION_WIDTH),
            condition_ink,
        ),
        off,
        glyphs(
            lpad(&table::clip(&action, ACTION_WIDTH), ACTION_WIDTH),
            action_ink,
        ),
    );

    let toggle = button(cells)
        .width(Length::Fill)
        .padding(ROW_PADDING)
        // Волна помечает включённое: «какие сейчас работают» видно боковым зрением.
        .style(table::row_style(rule.enabled))
        .on_press(Message::SplitTunnel(SplitTunnelMessage::RuleToggled(
            index,
            !rule.enabled,
        )));

    Flex::row()
        .push(toggle)
        .push_auto(table::action(
            crate::i18n::s().remove,
            REMOVE_WIDTH,
            Message::SplitTunnel(SplitTunnelMessage::RuleRemoved(index)),
        ))
        .gap(gap::NONE)
        .align(Alignment::Center)
        .build()
}

/// Ряд ячеек — общий для шапки и строк, чтобы столбцы не разъезжались.
fn columns<'a, Message: 'a>(
    name: Element<'a, Message>,
    condition: Element<'a, Message>,
    off: Option<Element<'a, Message>>,
    action: Element<'a, Message>,
) -> Element<'a, Message> {
    let mut line = Flex::row()
        .w(Size::FILL)
        .push_auto(name)
        .push_auto(condition);

    // «Выкл» стоит до распорки, иначе действие съезжает на таких строках.
    if let Some(off) = off {
        line = line.push_auto(off);
    }

    line.push(ui::spring())
        .push_auto(action)
        .gap(CELL)
        .align(Alignment::Center)
        .build()
}

#[cfg(test)]
mod tests {
    use iced::Color;
    use penguin_config::schema::rule::RuleAction;
    use serde_json::json;

    use super::*;

    fn state_with_rules(rules: serde_json::Value) -> State {
        let mut state = State::default();
        state.config.routing.rules = serde_json::from_value(rules).expect("правила разбираются");
        state
    }

    #[test]
    fn the_tab_fills_the_window() {
        let state = state_with_rules(json!([]));
        let size = view(&state).as_widget().size();

        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn an_empty_ruleset_says_why_it_is_empty() {
        let state = State::default();
        assert!(state.config.routing.rules.is_empty());
        let _ = view(&state);
    }

    #[test]
    fn rules_render() {
        let state = state_with_rules(json!([
            { "id": "r1", "name": "Игры мимо", "when": { "process_name": ["steam.exe"] }, "action": "direct" },
            { "id": "r2", "name": "Локальная сеть", "when": { "dest_ip": ["10.0.0.0/8"] }, "action": "direct" }
        ]));
        assert_eq!(state.config.routing.rules.len(), 2);
        let _ = view(&state);
    }

    #[test]
    fn saving_appears_only_with_changes() {
        let mut state = state_with_rules(json!([]));
        assert!(!state.dirty);
        let _ = view(&state);

        state.dirty = true;
        let _ = view(&state);
    }

    #[test]
    fn a_long_ruleset_renders() {
        let rules: Vec<serde_json::Value> = (0..30)
            .map(|index| {
                json!({
                    "id": format!("r{index}"),
                    "name": format!("Правило {index}"),
                    "when": { "dest_port": [443] },
                    "action": "direct"
                })
            })
            .collect();
        let _ = view(&state_with_rules(json!(rules)));
    }

    #[test]
    fn columns_never_shift_between_the_head_and_a_row() {
        let dim = Color::WHITE;
        let head: Element<'_, Message> = columns(
            glyphs(pad("ПРАВИЛО", NAME_WIDTH), dim),
            glyphs(pad("УСЛОВИЕ", CONDITION_WIDTH), dim),
            None,
            glyphs(lpad("ДЕЙСТВИЕ", ACTION_WIDTH), dim),
        );
        let row: Element<'_, Message> = columns(
            glyphs(pad("Игры мимо", NAME_WIDTH), dim),
            glyphs(pad("приложение: steam.exe", CONDITION_WIDTH), dim),
            None,
            glyphs(lpad("напрямую", ACTION_WIDTH), dim),
        );

        assert_eq!(head.as_widget().size(), row.as_widget().size());
    }

    #[test]
    fn every_action_keeps_the_width_of_its_column() {
        for action in [
            RuleAction::Direct,
            RuleAction::Block,
            RuleAction::Tunnel { profile: None },
            RuleAction::Tunnel {
                profile: Some("office".to_owned()),
            },
        ] {
            let described = describe_action(&action);
            let placed = lpad(&table::clip(&described, ACTION_WIDTH), ACTION_WIDTH);
            assert_eq!(
                placed.chars().count(),
                ACTION_WIDTH,
                "`{described}` не встало в столбец действия"
            );
        }
    }

    #[test]
    fn a_disabled_rule_stays_in_the_table() {
        let state = state_with_rules(json!([
            { "id": "r1", "name": "Выключено", "enabled": false,
              "when": { "dest_port": [443] }, "action": "direct" }
        ]));
        assert!(!state.config.routing.rules[0].enabled);
        let _ = view(&state);
    }

    #[test]
    fn search_looks_at_the_name_the_condition_and_the_action() {
        let rule: RuleConfig = serde_json::from_value(json!({
            "id": "r1",
            "name": "Игры мимо",
            "when": { "process_name": ["steam.exe"] },
            "action": "block"
        }))
        .expect("правило разбирается");

        assert!(found(&rule, ""));
        assert!(found(&rule, "игры"));
        assert!(found(&rule, "STEAM"));
        assert!(found(&rule, crate::i18n::s().action_block));
        assert!(!found(&rule, "нет такого"));
    }

    #[test]
    fn search_keeps_the_place_of_a_rule_in_the_set() {
        // Место — приоритет и номер в сообщении об удалении.
        let mut state = state_with_rules(json!([
            { "id": "r1", "name": "Первое", "when": { "dest_port": [80] }, "action": "direct" },
            { "id": "r2", "name": "Второе", "when": { "dest_port": [443] }, "action": "block" }
        ]));
        state.split_tunnel.search = "Второе".to_owned();

        let places: Vec<usize> = state
            .config
            .routing
            .rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| found(rule, &state.split_tunnel.search))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(places, [1]);

        let _ = view(&state);
    }

    #[test]
    fn a_search_that_finds_nothing_says_so() {
        let mut state = state_with_rules(json!([
            { "id": "r1", "name": "Первое", "when": { "dest_port": [80] }, "action": "direct" }
        ]));
        state.split_tunnel.search = "нет такого".to_owned();
        let _ = view(&state);
    }
}
