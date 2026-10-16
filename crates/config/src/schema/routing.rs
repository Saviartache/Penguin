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
            mode: TunnelMode::Tunnel,
            rules: Vec::new(),
            resolve_process: true,
            sniff: true,
        }
    }
}

/// Что делать с соединением, не подошедшим ни под одно правило («всё остальное»).
///
/// Правила действуют всегда и сильнее режима. Прежние имена схемы 2 читаются:
/// `full` и `blocklist` вели в тоннель, `allowlist` и `off` — напрямую.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    /// В тоннель через текущий сервер.
    #[default]
    #[serde(alias = "full", alias = "blocklist")]
    Tunnel,
    /// Мимо тоннеля.
    #[serde(alias = "allowlist", alias = "off")]
    Direct,
    /// Оборвать.
    Block,
}

impl TunnelMode {
    /// Все режимы в порядке показа.
    pub const ALL: [Self; 3] = [Self::Tunnel, Self::Direct, Self::Block];

    /// Имя в файле и в канале управления.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tunnel => "tunnel",
            Self::Direct => "direct",
            Self::Block => "block",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(name: &str) -> TunnelMode {
        serde_json::from_value(serde_json::json!(name)).expect("режим разбирается")
    }

    #[test]
    fn schema_2_names_keep_their_meaning() {
        assert_eq!(read("full"), TunnelMode::Tunnel);
        assert_eq!(read("blocklist"), TunnelMode::Tunnel);
        assert_eq!(read("allowlist"), TunnelMode::Direct);
        assert_eq!(read("off"), TunnelMode::Direct);
    }

    #[test]
    fn every_mode_is_written_by_its_name() {
        for mode in TunnelMode::ALL {
            assert_eq!(read(mode.as_str()), mode);
        }
    }
}
