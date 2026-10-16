//! Режим тоннелирования и список правил.

use serde::{Deserialize, Serialize};

use super::rule::RuleConfig;

/// Маршрутизация: умолчание и правила.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingConfig {
    /// Что делать с соединением, не подошедшим ни под одно правило.
    pub mode: TunnelMode,
    /// Правила; при равном приоритете раньше проверяется верхнее.
    pub rules: Vec<RuleConfig>,
    /// Определять процесс-владельца (системный вызов на каждое соединение).
    pub resolve_process: bool,
    /// Читать имя хоста из первых байт соединения (SNI, `Host`).
    pub sniff: bool,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            mode: TunnelMode::Full,
            rules: Vec::new(),
            resolve_process: true,
            sniff: true,
        }
    }
}

/// Умолчание для соединений, не подошедших ни под одно правило.
///
/// Правила действуют всегда и сильнее режима.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    /// Весь трафик в тоннель, кроме описанного правилами.
    #[default]
    Full,
    /// В тоннель — только то, что описано правилами.
    Allowlist,
    /// Как `full`, отличается только подсказками в интерфейсе.
    Blocklist,
    /// Тоннель выключен, правила разбираются.
    Off,
}

impl TunnelMode {
    /// Умолчание — тоннель.
    pub const fn defaults_to_tunnel(self) -> bool {
        matches!(self, Self::Full | Self::Blocklist)
    }

    /// Имя для интерфейса.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Allowlist => "allowlist",
            Self::Blocklist => "blocklist",
            Self::Off => "off",
        }
    }
}
