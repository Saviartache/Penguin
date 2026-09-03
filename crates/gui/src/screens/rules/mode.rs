//! Выбор режима: всё, белый список, чёрный список, только правила.
//!
//! Стоит первым на вкладке, на том же месте, где на вкладке серверов стоят
//! кнопки, и растянут во всю ширину. Причина не в красоте ряда: режим решает,
//! что происходит с трафиком, **о котором не сказано ничего**, — то есть с
//! почти всем. Правила уточняют уже его решение, и читать их, не зная режима,
//! бессмысленно.
//!
//! В списке показываются подписи, а в настройки уезжает значение
//! ([`crate::i18n::MODE_VALUES`]). Разделены они не ради перевода: значения
//! читает маршрутизатор и они не меняются никогда, а подписи меняются каждый
//! раз, когда выясняется, что человек понял их не так.
//!
//! Строки-объяснения под списком нет: подписи режимов сами говорят, что делают
//! («TUN: только правила», «TUN: кроме правил»), а строка под ними пересказывала
//! бы выбранную подпись другими словами и отодвигала бы вниз таблицу.

use iced::Element;
use uikit::widgets::Select;

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;

/// Режим в выпадающем списке.
///
/// Обёртка нужна затем, что список показывает варианты через `ToString`: без
/// неё пользователь читал бы в нём `allowlist`, а не «Только выбранное — в
/// тоннель».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Choice(pub &'static str);

impl Choice {
    /// Все режимы в порядке показа.
    pub fn all() -> Vec<Self> {
        crate::i18n::MODE_VALUES.map(Self).to_vec()
    }
}

impl std::fmt::Display for Choice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(crate::i18n::mode_label(self.0))
    }
}

/// Собирает верх вкладки: список режима во всю ширину.
pub fn view(state: &State) -> Element<'_, Message> {
    let current = state.config.routing.mode.as_str();

    Select::new(Choice::all(), Some(Choice(current)), |choice: Choice| {
        Message::SplitTunnel(SplitTunnelMessage::ModeSelected(choice.0.to_owned()))
    })
    .view()
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::routing::TunnelMode;

    use super::*;

    #[test]
    fn every_mode_is_shown_by_its_label() {
        // Без обёртки пользователь читал бы в списке `allowlist`.
        for choice in Choice::all() {
            assert_eq!(choice.to_string(), crate::i18n::mode_label(choice.0));
            assert_ne!(choice.to_string(), choice.0);
        }
    }

    #[test]
    fn every_mode_of_the_router_is_offered() {
        // Режим, которого нет в списке, но есть в файле, оставил бы список
        // пустым и режим неизменяемым.
        let offered: Vec<&str> = Choice::all().into_iter().map(|choice| choice.0).collect();
        for mode in [
            TunnelMode::Full,
            TunnelMode::Allowlist,
            TunnelMode::Blocklist,
            TunnelMode::Off,
        ] {
            assert!(
                offered.contains(&mode.as_str()),
                "режим `{mode:?}` не предлагается"
            );
        }
    }

    #[test]
    fn the_select_fills_the_width() {
        // Режим — самое важное решение на экране, и полем в треть ширины он
        // читался бы как одна из настроек.
        let state = State::default();
        assert_eq!(
            view(&state).as_widget().size().width,
            iced::Length::Fill,
            "список режима не во всю ширину"
        );
    }

    #[test]
    fn renders_in_every_mode() {
        let mut state = State::default();
        for mode in [
            TunnelMode::Full,
            TunnelMode::Allowlist,
            TunnelMode::Blocklist,
            TunnelMode::Off,
        ] {
            state.config.routing.mode = mode;
            let _ = view(&state);
        }
    }
}
