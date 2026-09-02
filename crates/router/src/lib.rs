//! Решение о судьбе соединения: в тоннель, напрямую или заблокировать.
//!
//! ```text
//!   контекст соединения (адреса, имя, процесс)
//!         │
//!         ├─ кэш решений ──────────► попадание ──► готово
//!         ├─ правила по порядку ───► первое совпавшее ──► готово
//!         └─ умолчание режима
//! ```
//!
//! Три вещи, которые стоит знать про этот крейт.
//!
//! **Режим — это только умолчание.** Правила действуют всегда и всегда
//! сильнее. «Белый и чёрный список одновременно» получается сам собой, без
//! отдельной ветки кода.
//!
//! **Условие — дерево.** `all` / `any` / `not` любой глубины над листьями:
//! приложение, домен, подсеть, порт, страна, вид трафика. Поэтому правило
//! «Chrome напрямую, но его обращения к банку — в тоннель» записывается
//! буквально.
//!
//! **Каждое решение несёт причину.** [`mod@explain`] показывает, какое правило
//! сработало и какие сработали бы без него. Без этого набор из тридцати
//! правил — чёрный ящик.

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
