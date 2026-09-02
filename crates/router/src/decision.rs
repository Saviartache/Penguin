//! `Decision` — исчерпывающий список исходов.
//!
//! Новый исход добавляется здесь, и компилятор находит все места, где его
//! забыли обработать.

use std::fmt;

use penguin_core::id::{OutboundId, RuleId};
use serde::{Deserialize, Serialize};

/// Что сделать с соединением.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Отправить через указанное направление.
    Tunnel(OutboundId),
    /// Отправить через активный профиль, какой бы он ни был.
    ///
    /// Отдельный вариант, а не подставленный при сборке идентификатор:
    /// пользователь переключает сервер, не трогая правила, и пересобирать
    /// из-за этого весь набор было бы расточительно — а главное, правило
    /// «в тоннель» и должно означать «в тот, который сейчас».
    ActiveTunnel,
    /// Выпустить напрямую, мимо тоннеля.
    Direct,
    /// Оборвать. Приложение получит отказ в соединении.
    Block,
}

impl Decision {
    /// Разрешает [`Self::ActiveTunnel`] в конкретное направление.
    pub fn resolve(&self, active: &OutboundId) -> ResolvedDecision {
        match self {
            Self::Tunnel(id) => ResolvedDecision::Tunnel(id.clone()),
            Self::ActiveTunnel => ResolvedDecision::Tunnel(active.clone()),
            Self::Direct => ResolvedDecision::Direct,
            Self::Block => ResolvedDecision::Block,
        }
    }
}

/// Решение, в котором направление уже названо.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedDecision {
    /// В тоннель через это направление.
    Tunnel(OutboundId),
    /// Напрямую.
    Direct,
    /// Оборвать.
    Block,
}

impl fmt::Display for ResolvedDecision {
    /// Коротким словом, а не фразой.
    ///
    /// Решение стоит в **каждой** строке журнала соединений, и «в тоннель
    /// (source)» вытесняет из строки то, ради чего её и читают, — куда шло
    /// соединение и чьё оно.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tunnel(id) => write!(f, "proxy[{id}]"),
            Self::Direct => f.write_str("direct"),
            Self::Block => f.write_str("block"),
        }
    }
}

/// Решение вместе с причиной.
///
/// Причина не для журнала: её показывает экран проверки правил в GUI. Без неё
/// набор из тридцати правил становится чёрным ящиком, и единственный способ
/// понять, почему приложение пошло не туда, — выключать правила по одному.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Что делать с соединением.
    pub decision: ResolvedDecision,
    /// Почему.
    pub reason: Reason,
}

impl Verdict {
    /// Решение по правилу.
    pub fn by_rule(decision: ResolvedDecision, rule: RuleId, name: impl Into<String>) -> Self {
        Self {
            decision,
            reason: Reason::Rule {
                id: rule,
                name: name.into(),
            },
        }
    }

    /// Решение по умолчанию режима.
    pub fn by_mode(decision: ResolvedDecision) -> Self {
        Self {
            decision,
            reason: Reason::Mode,
        }
    }

    /// То же решение, помеченное как взятое из кэша.
    pub fn cached(self) -> Self {
        match self.reason {
            // Второй раз оборачивать незачем: причина от этого не меняется.
            Reason::Cached(_) => self,
            reason => Self {
                decision: self.decision,
                reason: Reason::Cached(Box::new(reason)),
            },
        }
    }
}

/// Отчего получилось именно такое решение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// Сработало правило.
    Rule {
        /// Идентификатор правила.
        id: RuleId,
        /// Имя правила — его и показывает интерфейс.
        name: String,
    },
    /// Ни одно правило не подошло — применилось умолчание режима.
    Mode,
    /// Решение взято из кэша по предыдущему такому же соединению.
    Cached(Box<Reason>),
    /// Направление не умеет то, что от него требовалось (например, UDP),
    /// и соединение отправлено запасным путём.
    Fallback(&'static str),
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rule { name, .. } => write!(f, "правило «{name}»"),
            Self::Mode => f.write_str("умолчание режима"),
            Self::Cached(inner) => write!(f, "{inner} (из кэша)"),
            Self::Fallback(why) => write!(f, "запасной путь: {why}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_tunnel_resolves_to_the_current_profile() {
        let active = OutboundId::new("home");
        assert_eq!(
            Decision::ActiveTunnel.resolve(&active),
            ResolvedDecision::Tunnel(OutboundId::new("home"))
        );
    }

    #[test]
    fn explicit_profile_wins_over_the_active_one() {
        let active = OutboundId::new("home");
        let decision = Decision::Tunnel(OutboundId::new("office"));
        assert_eq!(
            decision.resolve(&active),
            ResolvedDecision::Tunnel(OutboundId::new("office"))
        );
    }

    #[test]
    fn cached_wraps_the_reason_once() {
        let verdict = Verdict::by_mode(ResolvedDecision::Direct).cached().cached();
        // Двойная обёртка сделала бы объяснение нечитаемым.
        assert!(matches!(verdict.reason, Reason::Cached(inner) if *inner == Reason::Mode));
    }

    #[test]
    fn reason_reads_as_a_sentence() {
        let verdict = Verdict::by_rule(
            ResolvedDecision::Direct,
            RuleId::new("r1"),
            "Игры мимо тоннеля",
        );
        assert_eq!(verdict.reason.to_string(), "правило «Игры мимо тоннеля»");
        assert_eq!(
            verdict.cached().reason.to_string(),
            "правило «Игры мимо тоннеля» (из кэша)"
        );
    }
}
