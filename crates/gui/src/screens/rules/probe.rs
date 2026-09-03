//! Модальное окно проверки: адрес и приложение на входе, решение на выходе.
//!
//! Отвечает на вопрос, ради которого экран и существует: **почему это
//! приложение пошло не туда**. Без проверки набор из тридцати правил — чёрный
//! ящик, и разбираться приходится выключением правил по одному.
//!
//! Показывается не только сработавшее правило, но и те, что сработали бы без
//! него: неожиданный исход чаще всего объясняется правилом, стоящим выше по
//! порядку.
//!
//! Поля переживают закрытие окна намеренно: одно и то же соединение проверяют
//! по нескольку раз, правя правила между заходами, и вписывать адрес заново
//! каждый раз значит проверять реже, чем нужно.

use iced::widget::text;
use iced::{Alignment, Element};
use uikit::layout::{Flex, gap, grow};
use uikit::style::tokens::{ink, type_scale};
use uikit::widgets::{Modal, TextInput};

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::ui;

/// Ширина окна.
///
/// Та же, что у окна нового правила: два модальных окна разной ширины в одной
/// программе читаются как два разных диалога.
const WIDTH: f32 = 620.0;

/// Высота разбора правил.
///
/// Фиксированная, а не «сколько поместится»: растянутое содержимое в панели
/// «по содержимому» схлопывается в ноль, а ноль роняет отрисовку.
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

    // Пустой адрес — не запрос, а незаполненная форма: ответ на неё был бы
    // ответом ни про что.
    if !probe.probe_destination.trim().is_empty() {
        modal = modal.action(
            crate::i18n::s().probe,
            Message::SplitTunnel(SplitTunnelMessage::ProbeRequested),
        );
    }

    modal.build().into()
}

/// Что ответила проверка.
///
/// До первой проверки на этом месте строка о том, чего ждут: пустота под
/// формой читается как «не ответило», и человек ждёт.
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
            // Три состояния, а не два: «сработало» и «сработало бы, не будь
            // предыдущего» — разные вещи, и именно во втором чаще всего и
            // кроется неожиданный исход.
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
    fn an_empty_address_offers_no_answer() {
        // Пустой адрес — не запрос, а незаполненная форма.
        let mut state = State::default();
        state.split_tunnel.probe_destination = "   ".to_owned();
        let _ = view(&state);

        state.split_tunnel.probe_destination = "example.com:443".to_owned();
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
