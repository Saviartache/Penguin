//! Правило: условие, действие, приоритет, признак включённости.
//!
//! Скомпилированная форма [`penguin_config::schema::rule::RuleConfig`].
//! Разница существенная: в конфигурации условие — это текст, здесь — готовое
//! дерево сопоставителей с построенными индексами. Regex компилируется один
//! раз, CIDR складываются в дерево, домены — в автомат Ахо — Корасик.

use penguin_core::id::RuleId;
use penguin_match::matcher::Matcher;
use penguin_match::target::MatchTarget;

use crate::decision::Decision;

/// Готовое к применению правило.
pub struct Rule {
    /// Идентификатор — он же попадает в объяснение решения.
    pub id: RuleId,
    /// Имя для интерфейса.
    pub name: String,
    /// Чем меньше, тем раньше проверяется.
    pub priority: i32,
    /// Условие.
    pub condition: Box<dyn Matcher>,
    /// Что делать при совпадении.
    pub action: Decision,
}

impl std::fmt::Debug for Rule {
    /// Условие выводится описанием, а не структурой: `Matcher` — это
    /// поведение, а не данные, и `Debug` у него намеренно нет.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rule")
            .field("id", &self.id.as_str())
            .field("name", &self.name)
            .field("priority", &self.priority)
            .field("condition", &self.condition.describe())
            .field("action", &self.action)
            .finish()
    }
}

impl Rule {
    /// Подходит ли правило под соединение.
    pub fn matches(&self, target: &MatchTarget<'_>) -> bool {
        self.condition.matches(target)
    }
}
