//! Режим тоннелирования и список правил.

use serde::{Deserialize, Serialize};

use super::rule::RuleConfig;

/// Маршрутизация: умолчание и правила.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingConfig {
    /// Что делать с соединением, не подошедшим ни под одно правило.
    pub mode: TunnelMode,
    /// Правила. Порядок в файле — часть смысла: при равном приоритете
    /// раньше проверяется то, что выше.
    pub rules: Vec<RuleConfig>,
    /// Определять процесс-владельца для каждого соединения.
    ///
    /// Выключается, если правил по процессам нет: чтение таблицы соединений
    /// стоит системного вызова на каждое новое соединение, и платить за него
    /// впустую незачем.
    pub resolve_process: bool,
    /// Читать имя хоста из первых байт соединения (SNI, `Host`).
    ///
    /// Без этого правила по доменам не действуют на приложения, которые
    /// разрешили имя заранее и пошли по адресу.
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
/// Режим — это не отдельная ветка логики, а именно умолчание. Правила
/// действуют всегда и всегда сильнее.
///
/// | Режим | Умолчание | Что пишет пользователь |
/// |---|---|---|
/// | `full` | в тоннель | исключения: `direct` |
/// | `allowlist` | напрямую | что пустить в тоннель: `tunnel` |
/// | `blocklist` | в тоннель | что оставить снаружи: `direct` |
/// | `off` | напрямую | ничего |
///
/// «Белый и чёрный список одновременно» — не отдельный режим, а следствие:
/// правила обоих действий в одном наборе, разбирает их порядок.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    /// Весь трафик в тоннель, кроме описанного правилами.
    #[default]
    Full,
    /// В тоннель — только то, что описано правилами.
    Allowlist,
    /// В тоннель всё, кроме описанного правилами. От `full` отличается только
    /// подсказками в интерфейсе: движок тот же.
    Blocklist,
    /// Тоннель выключен, но правила продолжают разбираться — так проверяют
    /// набор правил, не поднимая соединения.
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
