//! Вкладка правил: кнопки, группы сверху вниз, под ними «всё остальное».
//!
//! Та же таблица ([`crate::screens::table`]), что у серверов: значения сравнивают
//! между строками. Главный столбец — что группа заберёт, описывается тем же
//! кодом, что и в проверке ([`super::describe`]). Порядок на экране — порядок
//! проверки: первая подошедшая группа забирает соединение.
//!
//! Форма и проверка живут в модальных окнах, у вкладки нет своей прокрутки.
//! Выключенная группа приглушена и помечена словом: вычёркивания нет в шрифте,
//! а спрятанную группу ищут и не находят.

use iced::widget::button;
use iced::{Alignment, Element, Length};
use penguin_config::schema::rule::RuleConfig;
use uikit::layout::{Flex, Sizable, Size, gap, px};
use uikit::tokens::{ink, type_scale};
use uikit::widgets::ButtonVariant;

use crate::app::TAB_GAP;
use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::forms::rule;
use crate::screens::rules::describe::{condition_values, describe_action, describe_condition};
use crate::screens::rules::mode;
use crate::screens::table::{
    self, BUTTON_HEIGHT, CELL, ROW_GAP, ROW_PADDING, cell, glyphs, lpad, pad,
};
use crate::ui;

/// Ширина столбца имени в знаках: имя и есть то, по чему группу узнают.
/// Длинное режется, а не двигает условие. Условие — резиновое: забирает всё
/// место между именем и действием.
const NAME_WIDTH: usize = 26;

/// Ширина столбца действия: «через тоннель» и «заблокировать» целиком.
const ACTION_WIDTH: usize = 14;

/// Зазор между столбцами в знаках: в один знак соседние столбцы читаются
/// одной фразой.
const COLUMN_GAP: f32 = 2.0;

/// Ширина переключателя `[ВЫКЛ]` в точках.
const TOGGLE_WIDTH: f32 = 56.0;

/// Ширина кнопки в один знак: выше, ниже, удалить.
const GLYPH_WIDTH: f32 = 30.0;

/// Место под кнопки строки — его же оставляет шапка.
const ACTIONS_WIDTH: f32 = TOGGLE_WIDTH + GLYPH_WIDTH * 3.0;

/// Выше.
const UP: &str = "↑";

/// Ниже.
const DOWN: &str = "↓";

/// Удалить; `✕` в ZedMono нет, запасной шрифт шире ячейки.
const REMOVE: &str = "×";

/// Собирает вкладку целиком.
pub fn view(state: &State) -> Element<'_, Message> {
    Flex::col()
        .w(Size::FILL)
        .h(Size::FILL)
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
                .on_press(Message::SplitTunnel(SplitTunnelMessage::EditorOpened(None))),
        )
        .push_auto(
            ui::button(ButtonVariant::Secondary, crate::i18n::s().probe_rule)
                .h(px(BUTTON_HEIGHT))
                .on_press(Message::SplitTunnel(SplitTunnelMessage::ProbeOpened)),
        );

    // Пока системное окно открыто, второе такое же не нужно.
    for (label, message) in [
        (
            crate::i18n::s().import_rules,
            SplitTunnelMessage::ImportRequested,
        ),
        (
            crate::i18n::s().export_rules,
            SplitTunnelMessage::ExportRequested,
        ),
    ] {
        let mut button = ui::button(ButtonVariant::Secondary, label).h(px(BUTTON_HEIGHT));
        if !state.split_tunnel.picking {
            button = button.on_press(Message::SplitTunnel(message));
        }
        row = row.push_auto(button);
    }

    if let Some(report) = state.split_tunnel.import_report.as_deref() {
        row = row.push_auto(ui::muted(&state.palette, report, type_scale::MICRO));
    }
    row = row.push(ui::spring());

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
        Flex::col()
            .w(Size::FILL)
            .h(Size::FILL)
            .push(rows(state))
            .push_auto(mode::view(state))
            .gap(gap::XS)
            .build(),
        crate::i18n::s().toggle_hint,
    )
}

/// Шапка таблицы с тем же отступом и местом под «удалить», что у строки.
fn head(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    let dim = ink::level(&state.palette, ink::TERTIARY);

    let titles = columns(
        glyphs(pad(strings.rule, NAME_WIDTH), dim),
        glyphs(strings.condition, dim),
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
        .push_auto(iced::widget::Space::new().width(Length::Fixed(ACTIONS_WIDTH)))
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

    let last = rules.len() - 1;
    let list = Flex::col()
        .w(Size::FILL)
        .extend(
            shown
                .into_iter()
                .map(|(index, rule)| row(state, index, last, rule)),
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
    let values = condition_values(&rule.when);

    let mut fields = vec![rule.name.as_str(), &rule.id, &condition, &action];
    fields.extend(values.iter().map(String::as_str));
    table::matches(query, &fields)
}

/// Строка группы: щелчок открывает правку, справа — вкл/выкл, порядок, удаление.
/// Правило, написанное в файле руками, форма не откроет — строка не нажимается.
fn row<'a>(
    state: &'a State,
    index: usize,
    last: usize,
    rule: &'a RuleConfig,
) -> Element<'a, Message> {
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
        glyphs(describe_condition(&rule.when), condition_ink),
        off,
        glyphs(
            lpad(&table::clip(&action, ACTION_WIDTH), ACTION_WIDTH),
            action_ink,
        ),
    );

    let edit = button(cells)
        .width(Length::Fill)
        .padding(ROW_PADDING)
        // Волна помечает включённое: «какие сейчас работают» видно боковым зрением.
        .style(table::row_style(rule.enabled))
        .on_press_maybe(
            rule::load(index, rule)
                .map(|_| Message::SplitTunnel(SplitTunnelMessage::EditorOpened(Some(index)))),
        );

    let strings = crate::i18n::s();
    let switch = if rule.enabled {
        strings.on
    } else {
        strings.off
    };

    Flex::row()
        .push(edit)
        .push_auto(table::action(
            switch,
            TOGGLE_WIDTH,
            Message::SplitTunnel(SplitTunnelMessage::RuleToggled(index, !rule.enabled)),
        ))
        .push_auto(shift(index.checked_sub(1), index, UP))
        .push_auto(shift((index < last).then_some(index + 1), index, DOWN))
        .push_auto(table::action(
            REMOVE,
            GLYPH_WIDTH,
            Message::SplitTunnel(SplitTunnelMessage::RuleRemoved(index)),
        ))
        .gap(gap::NONE)
        .align(Alignment::Center)
        .build()
}

/// Кнопка перестановки; у края списка — пустое место той же ширины.
fn shift<'a>(to: Option<usize>, from: usize, glyph: &str) -> Element<'a, Message> {
    match to {
        Some(to) => table::action(
            glyph,
            GLYPH_WIDTH,
            Message::SplitTunnel(SplitTunnelMessage::RuleMoved(from, to)),
        ),
        None => iced::widget::Space::new()
            .width(Length::Fixed(GLYPH_WIDTH))
            .into(),
    }
}

/// Ряд ячеек — общий для шапки и строк, чтобы столбцы не разъезжались.
fn columns<'a, Message: 'a>(
    name: Element<'a, Message>,
    condition: Element<'a, Message>,
    off: Option<Element<'a, Message>>,
    action: Element<'a, Message>,
) -> Element<'a, Message> {
    // Условие забирает всё свободное место; не влезшее срезается краем, а не
    // наезжает на действие.
    let condition = iced::widget::container(condition)
        .width(Length::Fill)
        .clip(true);
    let mut line = Flex::row().w(Size::FILL).push_auto(name).push(condition);

    // «Выкл» — перед действием: столбцы слева от него не сдвигаются.
    if let Some(off) = off {
        line = line.push_auto(off);
    }

    line.push_auto(action)
        .gap(CELL * COLUMN_GAP)
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
            glyphs("УСЛОВИЕ", dim),
            None,
            glyphs(lpad("ДЕЙСТВИЕ", ACTION_WIDTH), dim),
        );
        let row: Element<'_, Message> = columns(
            glyphs(pad("Игры мимо", NAME_WIDTH), dim),
            glyphs("приложения: 1, домены и поддомены: 39", dim),
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
