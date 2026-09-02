//! `TunnelState` — состояние тоннеля как автомат, а не набор булевых флагов.
//!
//! Флаги `is_connected` и `is_connecting` рано или поздно оказываются
//! выставлены оба сразу, и интерфейс показывает то ли одно, то ли другое.
//! Перечисление такого состояния не допускает по построению.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::id::ProfileId;

/// Состояние тоннеля.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum TunnelState {
    /// Выключен. Трафик идёт как обычно.
    Disconnected,

    /// Поднимается.
    Connecting {
        /// К какому профилю.
        profile: ProfileId,
    },

    /// Работает.
    Connected {
        /// Через какой профиль.
        profile: ProfileId,
        /// Сколько секунд назад установлено. Не момент времени: часы у демона
        /// и у интерфейса разные, а разница длительностей одинаковая.
        uptime_secs: u64,
    },

    /// Соединение потеряно, идёт переподключение.
    Reconnecting {
        /// К какому профилю.
        profile: ProfileId,
        /// Какая это по счёту попытка.
        attempt: u32,
        /// Почему сорвалось в прошлый раз.
        reason: String,
    },

    /// Остановлен ошибкой, которая сама не пройдёт.
    Failed {
        /// Что случилось.
        reason: String,
    },

    /// Опускается.
    Disconnecting,
}

impl TunnelState {
    /// Трафик сейчас идёт через тоннель.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }

    /// Идёт работа: показывать индикатор ожидания.
    pub fn is_busy(&self) -> bool {
        matches!(
            self,
            Self::Connecting { .. } | Self::Reconnecting { .. } | Self::Disconnecting
        )
    }

    /// Профиль, к которому относится состояние.
    pub fn profile(&self) -> Option<&ProfileId> {
        match self {
            Self::Connecting { profile }
            | Self::Connected { profile, .. }
            | Self::Reconnecting { profile, .. } => Some(profile),
            Self::Disconnected | Self::Failed { .. } | Self::Disconnecting => None,
        }
    }
}

impl Default for TunnelState {
    fn default() -> Self {
        Self::Disconnected
    }
}

impl fmt::Display for TunnelState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected => f.write_str("отключён"),
            Self::Connecting { profile } => write!(f, "подключение к {profile}"),
            Self::Connected { profile, .. } => write!(f, "подключён к {profile}"),
            Self::Reconnecting { attempt, .. } => write!(f, "переподключение, попытка {attempt}"),
            Self::Failed { reason } => write!(f, "ошибка: {reason}"),
            Self::Disconnecting => f.write_str("отключение"),
        }
    }
}
