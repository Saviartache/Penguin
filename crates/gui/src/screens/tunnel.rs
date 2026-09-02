//! Как называется состояние тоннеля и каким цветом его показывать.
//!
//! Отдельно от экрана: подписи и исходы нужны и компактному окну, и журналу, а
//! перепутанный исход означает зелёную надпись на неработающем тоннеле — такое
//! проверяется тестом, а не глазами.

use penguin_core::state::TunnelState;
use uikit::widgets::ButtonVariant;

/// Что состояние означает: хорошо, идёт, плохо.
///
/// Три исхода, а не шесть цветов: цвет здесь — не украшение, а способ понять
/// состояние, не читая надписи, и различать больше трёх оттенков боковым
/// зрением всё равно не выходит.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Работает.
    Good,
    /// Переходное состояние: подключаемся, отключаемся, переподключаемся.
    Busy,
    /// Не работает и само не починится.
    Trouble,
}

impl Tone {
    /// Цвет этого исхода в текущей теме.
    pub fn color(self, palette: &iced::theme::Palette) -> iced::Color {
        match self {
            Self::Good => palette.success,
            // Переходное состояние — обычным цветом текста: красить его в
            // тревожный значит пугать тем, что идёт по плану.
            Self::Busy => palette.text,
            Self::Trouble => palette.danger,
        }
    }
}

/// Подпись и исход для состояния тоннеля.
///
/// Свободная функция с тестом: перепутать здесь исход означает зелёную надпись
/// на неработающем тоннеле.
pub fn describe(tunnel: &TunnelState) -> (String, Tone) {
    match tunnel {
        TunnelState::Connected { uptime_secs, .. } => (
            format!(
                "{} · {}",
                crate::i18n::s().connected,
                format_uptime(*uptime_secs)
            ),
            Tone::Good,
        ),
        TunnelState::Connecting { .. } => (crate::i18n::s().connecting.to_owned(), Tone::Busy),
        TunnelState::Reconnecting { attempt, .. } => (
            format!("{} ({attempt})", crate::i18n::s().reconnecting),
            Tone::Busy,
        ),
        TunnelState::Disconnecting => (crate::i18n::s().disconnecting.to_owned(), Tone::Busy),
        // Причина показывается как есть: «ошибка» без объяснения не помогает
        // никому, а места под неё в строке хватает.
        TunnelState::Failed { reason } => (reason.clone(), Tone::Trouble),
        TunnelState::Disconnected => (crate::i18n::s().disconnected.to_owned(), Tone::Busy),
    }
}

/// Подпись и вид кнопки для состояния.
///
/// Свободная функция с тестом: перепутать здесь вид означает красную кнопку
/// «Подключить» или зелёную «Отключить».
pub fn describe_button(tunnel: &TunnelState) -> (&'static str, ButtonVariant) {
    match tunnel {
        // Пока идёт переключение, кнопка означает «прервать»: другого
        // осмысленного действия у пользователя нет.
        TunnelState::Connected { .. }
        | TunnelState::Connecting { .. }
        | TunnelState::Reconnecting { .. } => (crate::i18n::s().disconnect, ButtonVariant::Danger),

        TunnelState::Disconnecting => (crate::i18n::s().disconnecting, ButtonVariant::Neutral),
        TunnelState::Disconnected | TunnelState::Failed { .. } => {
            (crate::i18n::s().connect, ButtonVariant::Primary)
        }
    }
}

/// Переводит время работы в читаемый вид.
pub fn format_uptime(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;

    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    }
}

#[cfg(test)]
mod tests {
    use penguin_core::id::ProfileId;

    use super::*;

    #[test]
    fn connected_reads_as_good_and_shows_uptime() {
        let (label, tone) = describe(&TunnelState::Connected {
            profile: ProfileId::new("home"),
            uptime_secs: 90,
        });
        assert_eq!(tone, Tone::Good);
        assert!(label.contains("1:30"), "время работы не показано: {label}");
    }

    #[test]
    fn failure_reads_as_trouble_and_shows_the_reason() {
        // Зелёная надпись на сломанном тоннеле — худшее, что может показать
        // экран.
        let (label, tone) = describe(&TunnelState::Failed {
            reason: "неверный пароль".to_owned(),
        });
        assert_eq!(tone, Tone::Trouble);
        assert_eq!(label, "неверный пароль");
    }

    #[test]
    fn transitional_states_are_not_alarming() {
        // Переходное состояние идёт по плану; красить его тревожным значит
        // пугать тем, что должно происходить.
        assert_eq!(describe(&TunnelState::Disconnecting).1, Tone::Busy);
        assert_eq!(describe(&TunnelState::Disconnected).1, Tone::Busy);
    }

    #[test]
    fn the_button_offers_the_opposite_of_what_is_happening() {
        let (label, variant) = describe_button(&TunnelState::Connected {
            profile: ProfileId::new("home"),
            uptime_secs: 0,
        });
        assert_eq!(label, crate::i18n::s().disconnect);
        assert_eq!(variant, ButtonVariant::Danger);

        let (label, variant) = describe_button(&TunnelState::Disconnected);
        assert_eq!(label, crate::i18n::s().connect);
        assert_eq!(variant, ButtonVariant::Primary);
    }

    #[test]
    fn after_a_failure_the_button_offers_to_try_again() {
        // Отключать нечего: тоннеля нет.
        let (label, _) = describe_button(&TunnelState::Failed {
            reason: "не вышло".to_owned(),
        });
        assert_eq!(label, crate::i18n::s().connect);
    }

    #[test]
    fn uptime_switches_to_hours() {
        assert_eq!(format_uptime(0), "0:00");
        assert_eq!(format_uptime(59), "0:59");
        assert_eq!(format_uptime(90), "1:30");
        assert_eq!(format_uptime(3661), "1:01:01");
    }
}
