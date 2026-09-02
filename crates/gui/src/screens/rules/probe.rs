//! Проверка правил: адрес и приложение на входе, решение на выходе.
//!
//! Отвечает на вопрос, ради которого экран и существует: **почему это
//! приложение пошло не туда**. Без проверки набор из тридцати правил — чёрный
//! ящик, и разбираться приходится выключением правил по одному.
//!
//! Показывается не только сработавшее правило, но и те, что сработали бы без
//! него: неожиданный исход чаще всего объясняется правилом, стоящим выше по
//! порядку.

use iced::widget::text;
use iced::{Alignment, Element};
use penguin_ipc::schema::Explanation;
use uikit::layout::{Flex, gap, grow};
use uikit::style::tokens::{ink, type_scale};
use uikit::widgets::{ButtonVariant, TextInput};

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::ui;

/// Собирает раздел проверки.
pub fn view(state: &State) -> Element<'_, Message> {
    let palette = &state.palette;
    let probe = &state.split_tunnel;

    let form = Flex::row()
        .push_sized(
            TextInput::new(crate::i18n::s().destination, &probe.probe_destination)
                .on_input(|value| {
                    Message::SplitTunnel(SplitTunnelMessage::ProbeDestinationChanged(value))
                })
                .build(),
            grow(3),
        )
        .push_sized(
            TextInput::new(crate::i18n::s().process, &probe.probe_process)
                .on_input(|value| {
                    Message::SplitTunnel(SplitTunnelMessage::ProbeProcessChanged(value))
                })
                .build(),
            grow(2),
        )
        .push_auto(
            ui::button(ButtonVariant::Secondary, crate::i18n::s().probe)
                .on_press(Message::SplitTunnel(SplitTunnelMessage::ProbeRequested)),
        )
        .gap(gap::SM)
        .align(Alignment::Center)
        .build();

    let content = Flex::col()
        .push_auto(form)
        .push_maybe(
            probe
                .probe_result
                .as_ref()
                .map(|answer| result(state, answer)),
        )
        .gap(gap::MD)
        .build();

    ui::section(palette, crate::i18n::s().rule_probe, None, content)
}

/// Показывает результат проверки.
fn result<'a>(state: &'a State, explanation: &'a Explanation) -> Element<'a, Message> {
    let palette = &state.palette;

    let verdict =
        text(format!("{} — {}", explanation.decision, explanation.reason)).size(type_scale::LEAD);

    let rows = explanation
        .rules
        .iter()
        .map(|rule| {
            // Три состояния, а не два: «сработало» и «сработало бы, не будь
            // предыдущего» — разные вещи, и именно во втором чаще всего и
            // кроется неожиданный исход.
            let (mark, level) = match (rule.decisive, rule.matched) {
                (true, _) => ("→", ink::SECONDARY),
                (false, true) => ("·", ink::TERTIARY),
                (false, false) => (" ", ink::TERTIARY),
            };
            let color = iced::theme::Text::Color(ink::level(palette, level));

            Flex::row()
                .push_auto(text(mark).size(type_scale::BODY).style(color))
                .push(
                    text(format!("{}  ({})", rule.name, rule.condition))
                        .size(type_scale::BODY)
                        .style(color),
                )
                .gap(gap::SM)
                .align(Alignment::Start)
                .build()
        })
        .collect::<Vec<Element<'a, Message>>>();

    Flex::col()
        .push_auto(verdict)
        .push_auto(Flex::col().extend(rows).gap(gap::XS).build())
        .gap(gap::SM)
        .build()
}

#[cfg(test)]
mod tests {
    use penguin_ipc::schema::RuleTrace;

    use super::*;

    fn explanation() -> Explanation {
        Explanation {
            decision: "напрямую".to_owned(),
            reason: "правило «Игры мимо»".to_owned(),
            rules: vec![
                RuleTrace {
                    id: "игры".to_owned(),
                    name: "Игры мимо".to_owned(),
                    condition: "имя в [steam.exe]".to_owned(),
                    matched: true,
                    decisive: true,
                },
                RuleTrace {
                    id: "всё".to_owned(),
                    name: "Всё остальное".to_owned(),
                    condition: "адрес в [0.0.0.0/0]".to_owned(),
                    matched: true,
                    decisive: false,
                },
            ],
        }
    }

    #[test]
    fn renders_before_the_first_check() {
        // До первой проверки результата нет — и это нормальное состояние.
        let state = State::default();
        assert!(state.split_tunnel.probe_result.is_none());
        let _ = view(&state);
    }

    #[test]
    fn renders_a_result() {
        let mut state = State::default();
        state.split_tunnel.probe_result = Some(explanation());
        let _ = view(&state);
    }

    #[test]
    fn only_one_rule_is_decisive() {
        // Два решающих правила означали бы, что порядок разбора нарушен.
        let decisive = explanation()
            .rules
            .iter()
            .filter(|rule| rule.decisive)
            .count();
        assert_eq!(decisive, 1);
    }

    #[test]
    fn a_shadowed_rule_is_distinguishable() {
        // Неожиданный исход чаще всего объясняется правилом, стоящим выше по
        // порядку, — его надо видеть.
        let explanation = explanation();
        let shadowed = explanation
            .rules
            .iter()
            .find(|rule| rule.matched && !rule.decisive);
        assert!(shadowed.is_some(), "перекрытое правило не показано");
    }
}
