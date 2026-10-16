//! Модальное окно проверки: адрес и приложение на входе, решение на выходе.
//!
//! Объясняет, почему приложение пошло не туда: показывает и сработавшее правило,
//! и те, что сработали бы без него (исход чаще всего объясняет правило выше по
//! порядку). Поля переживают закрытие: одно соединение проверяют по несколько
//! раз, правя правила.

use iced::widget::text;
use iced::{Alignment, Element};
use uikit::layout::{Flex, gap, grow};
use uikit::tokens::{ink, type_scale};
use uikit::widgets::{Modal, TextInput};

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::ui;

/// Ширина окна — как у окна нового правила.
const WIDTH: f32 = 620.0;

/// Высота разбора правил: фиксированная, растянутое схлопнулось бы в ноль.
const TRACE_HEIGHT: f32 = 180.0;

/// Собирает модальное окно проверки.
pub fn view(state: &State) -> Element<'_, Message> {
    let probe = &state.split_tunnel;

    let form = Flex::row()
        .push_sized(
            TextInput::new(crate::i18n::s().destination, &probe.probe_destination)
                .on_input(|value| {
                    Message::SplitTunnel(SplitTunnelMessage::ProbeDestinationChanged(value))
                })
                .on_submit(Message::SplitTunnel(SplitTunnelMessage::ProbeRequested))
                .build(),
            grow(3),
        )
        .push_sized(
            TextInput::new(crate::i18n::s().process, &probe.probe_process)
                .on_input(|value| {
                    Message::SplitTunnel(SplitTunnelMessage::ProbeProcessChanged(value))
                })
                .on_submit(Message::SplitTunnel(SplitTunnelMessage::ProbeRequested))
                .build(),
            grow(2),
        )
        .gap(gap::SM)
        .align(Alignment::Center)
        .build();

    let content = Flex::col()
        .push_auto(form)
        .push_auto(result(state))
        .gap(gap::MD)
        .build();

    let mut modal = Modal::new(content)
        .title(crate::i18n::s().rule_probe)
        .max_width(WIDTH)
        .on_close(Message::SplitTunnel(SplitTunnelMessage::ProbeClosed))
        .on_backdrop(Message::SplitTunnel(SplitTunnelMessage::ProbeClosed));

    // Пустой адрес — не запрос.
    if !probe.probe_destination.trim().is_empty() {
        modal = modal.action(
            crate::i18n::s().probe,
            Message::SplitTunnel(SplitTunnelMessage::ProbeRequested),
        );
    }

    modal.build().into()
}

/// Ответ проверки; до первой проверки — строка о том, чего ждут.
fn result(state: &State) -> Element<'_, Message> {
    let palette = &state.palette;
    let Some(explanation) = state.split_tunnel.probe_result.as_ref() else {
        return ui::empty(palette, crate::i18n::s().probe_hint);
    };

    let verdict =
        text(format!("{} — {}", explanation.decision, explanation.reason)).size(type_scale::LEAD);

    let rows = explanation
        .rules
        .iter()
        .map(|rule| {
            // Три состояния: «сработало» и «сработало бы, не будь предыдущего».
            let (mark, level) = match (rule.decisive, rule.matched) {
                (true, _) => (">", ink::SECONDARY),
                (false, true) => ("·", ink::TERTIARY),
                (false, false) => (" ", ink::TERTIARY),
            };
            let color = ink::level(palette, level);

            Flex::row()
                .push_auto(text(mark).size(type_scale::BODY).color(color))
                .push(
                    text(format!("{}  ({})", rule.name, rule.condition))
                        .size(type_scale::BODY)
                        .color(color),
                )
                .gap(gap::SM)
                .align(Alignment::Start)
                .build()
        })
        .collect::<Vec<Element<'_, Message>>>();

    Flex::col()
        .push_auto(verdict)
        .push_auto(ui::scroll_box(
            Flex::col().extend(rows).gap(gap::XS).build(),
            TRACE_HEIGHT,
        ))
        .gap(gap::SM)
        .build()
}

#[cfg(test)]
mod tests {
    use penguin_ipc::schema::{Explanation, RuleTrace};

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
    fn an_empty_address_offers_no_answer() {
        let mut state = State::default();
        state.split_tunnel.probe_destination = "   ".to_owned();
        let _ = view(&state);

        state.split_tunnel.probe_destination = "example.com:443".to_owned();
        let _ = view(&state);
    }

    #[test]
    fn only_one_rule_is_decisive() {
        let decisive = explanation()
            .rules
            .iter()
            .filter(|rule| rule.decisive)
            .count();
        assert_eq!(decisive, 1);
    }

    #[test]
    fn a_shadowed_rule_is_distinguishable() {
        let explanation = explanation();
        let shadowed = explanation
            .rules
            .iter()
            .find(|rule| rule.matched && !rule.decisive);
        assert!(shadowed.is_some(), "перекрытое правило не показано");
    }
}
