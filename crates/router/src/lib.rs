//! Решение о судьбе соединения: в тоннель, напрямую или заблокировать.
//!
//! Порядок: кэш решений, затем правила по порядку (первое совпавшее), затем
//! умолчание режима. Режим — только умолчание, правила всегда сильнее. Условие
//! — дерево `all`/`any`/`not`. Каждое решение несёт причину ([`mod@explain`]).

pub mod cache;
pub mod context;
pub mod decision;
pub mod engine;
pub mod error;
pub mod explain;
pub mod mode;
pub mod ruleset;

pub use cache::DecisionCache;
pub use context::FlowContext;
pub use decision::{Decision, Reason, ResolvedDecision, Verdict};
pub use engine::{Router, default_decision};
pub use error::{RouterError, RouterResult};
pub use explain::{Explanation, RuleTrace, explain};
pub use mode::TunnelMode;
pub use ruleset::{CompileContext, Rule, RuleSet};
