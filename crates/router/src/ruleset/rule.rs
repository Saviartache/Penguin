//! Скомпилированная форма [`penguin_config::schema::rule::RuleConfig`]:
//! готовое дерево сопоставителей вместо текста условия.

use penguin_core::id::RuleId;
use penguin_match::matcher::Matcher;
use penguin_match::target::MatchTarget;

use crate::decision::Decision;

/// Готовое к применению правило.
pub struct Rule {
    /// Идентификатор.
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
    /// Условие выводится описанием: у `Matcher` нет `Debug`.
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
