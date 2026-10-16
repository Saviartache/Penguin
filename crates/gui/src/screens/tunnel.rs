//! Подпись состояния тоннеля и его цвет. Отдельно от экрана: перепутанный исход —
//! зелёная надпись на неработающем тоннеле, это проверяется тестом.

use penguin_core::state::TunnelState;
use uikit::widgets::ButtonVariant;

/// Что состояние означает; три исхода, потому что больше оттенков боковым зрением не различить.
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
            // Переходное красить тревожным значит пугать тем, что идёт по плану.
            Self::Busy => palette.text,
            Self::Trouble => palette.danger,
        }
    }
}

/// Подпись и исход для состояния тоннеля.
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
        // Причина как есть: «ошибка» без объяснения не помогает.
        TunnelState::Failed { reason } => (reason.clone(), Tone::Trouble),
        TunnelState::Disconnected => (crate::i18n::s().disconnected.to_owned(), Tone::Busy),
    }
}

/// Подпись и вид кнопки; в переходных состояниях она означает «прервать».
pub fn describe_button(tunnel: &TunnelState) -> (&'static str, ButtonVariant) {
    match tunnel {
        TunnelState::Connected { .. }
        | TunnelState::Connecting { .. }
        | TunnelState::Reconnecting { .. } => (crate::i18n::s().disconnect, ButtonVariant::Danger),

        TunnelState::Disconnecting => (crate::i18n::s().disconnecting, ButtonVariant::Neutral),
        TunnelState::Disconnected | TunnelState::Failed { .. } => {
            (crate::i18n::s().connect, ButtonVariant::Primary)
        }
    }
}

/// Подпись и вид кнопки, пока служба не отвечает: подключаться не к кому, её надо запустить.
pub fn describe_service_button(starting: bool) -> (&'static str, ButtonVariant) {
    if starting {
        (crate::i18n::s().service_starting, ButtonVariant::Neutral)
    } else {
        (crate::i18n::s().start_service, ButtonVariant::Primary)
    }
}

/// Время работы: `1:30` или `1:01:01`.
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
        let (label, tone) = describe(&TunnelState::Failed {
            reason: "неверный пароль".to_owned(),
        });
        assert_eq!(tone, Tone::Trouble);
        assert_eq!(label, "неверный пароль");
    }

    #[test]
    fn transitional_states_are_not_alarming() {
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
        let (label, _) = describe_button(&TunnelState::Failed {
            reason: "не вышло".to_owned(),
        });
        assert_eq!(label, crate::i18n::s().connect);
    }

    #[test]
    fn without_the_service_the_button_starts_it() {
        assert_eq!(
            describe_service_button(false),
            (crate::i18n::s().start_service, ButtonVariant::Primary)
        );
        assert_eq!(describe_service_button(true).1, ButtonVariant::Neutral);
    }

    #[test]
    fn uptime_switches_to_hours() {
        assert_eq!(format_uptime(0), "0:00");
        assert_eq!(format_uptime(59), "0:59");
        assert_eq!(format_uptime(90), "1:30");
        assert_eq!(format_uptime(3661), "1:01:01");
    }
}
