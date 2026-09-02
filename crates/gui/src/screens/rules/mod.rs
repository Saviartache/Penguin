//! Раздельное тоннелирование: режим, правила, новое правило, проверка.
//!
//! Самый важный экран клиента и единственный, где пользователь принимает
//! решения, а не смотрит на результат. Отсюда порядок разделов:
//!
//! 1. **режим** — что происходит с трафиком, о котором не сказано ничего;
//! 2. **правила** — что происходит с остальным;
//! 3. **новое правило** — как добавить ещё одно;
//! 4. **проверка** — что случится с конкретным соединением.
//!
//! Четвёртый раздел не украшение. Набор из тридцати правил без проверки —
//! чёрный ящик, и единственный способ понять, почему приложение пошло не туда,
//! — выключать правила по одному.

pub mod editor;
pub mod list;
pub mod mode;
pub mod probe;

use iced::{Alignment, Element};
use uikit::layout::{Flex, gap};
use uikit::style::tokens::type_scale;
use uikit::widgets::ButtonVariant;

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::ui;

/// Собирает экран.
pub fn view(state: &State) -> Element<'_, Message> {
    let mut sections = vec![
        mode::view(state),
        list::view(state),
        editor::view(state),
        probe::view(state),
    ];
    if state.dirty {
        sections.push(unsaved(state));
    }

    // Без заголовка: название вкладки уже стоит над экраном, и повторять его
    // значит отдать две строки под то, что человек только что прочитал.
    ui::page_bare(sections)
}

/// Раздел сохранения.
///
/// Появляется только при несохранённых правках: постоянно видимая «Сохранить»
/// перестаёт что-либо значить, и её жмут на всякий случай.
fn unsaved(state: &State) -> Element<'_, Message> {
    let row = Flex::row()
        .push(ui::muted(
            &state.palette,
            crate::i18n::s().unsaved,
            type_scale::BODY,
        ))
        .push_auto(
            ui::button(ButtonVariant::Primary, crate::i18n::s().save)
                .on_press(Message::SplitTunnel(SplitTunnelMessage::Save)),
        )
        .gap(gap::SM)
        .align(Alignment::Center)
        .build();

    ui::section(&state.palette, crate::i18n::s().save, None, row)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn state_with_rules(rules: serde_json::Value) -> State {
        let mut state = State::default();
        state.config.routing.rules = serde_json::from_value(rules).expect("правила разбираются");
        state
    }

    #[test]
    fn an_empty_ruleset_renders() {
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
        // Тридцать правил — то, ради чего на экране есть проверка.
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
}
