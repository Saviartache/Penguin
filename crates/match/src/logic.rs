//! Комбинаторы «все», «любой», «не» для составных условий.

use crate::matcher::Matcher;
use crate::target::MatchTarget;

/// Все вложенные условия должны совпасть; пустой набор совпадает всегда.
pub struct All(pub Vec<Box<dyn Matcher>>);

/// Достаточно одного совпадения; пустой набор не совпадает никогда.
pub struct Any(pub Vec<Box<dyn Matcher>>);

/// Отрицание.
pub struct Not(pub Box<dyn Matcher>);

/// Совпадает всегда. Нужен как умолчание и как заглушка в тестах.
pub struct Always;

impl Matcher for All {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        self.0.iter().all(|matcher| matcher.matches(target))
    }

    fn describe(&self) -> String {
        if self.0.is_empty() {
            return "всегда".to_owned();
        }
        let parts: Vec<String> = self.0.iter().map(|m| m.describe()).collect();
        format!("({})", parts.join(" и "))
    }
}

impl Matcher for Any {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        self.0.iter().any(|matcher| matcher.matches(target))
    }

    fn describe(&self) -> String {
        if self.0.is_empty() {
            return "никогда".to_owned();
        }
        let parts: Vec<String> = self.0.iter().map(|m| m.describe()).collect();
        format!("({})", parts.join(" или "))
    }
}

impl Matcher for Not {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        !self.0.matches(target)
    }

    fn describe(&self) -> String {
        format!("не {}", self.0.describe())
    }
}

impl Matcher for Always {
    fn matches(&self, _target: &MatchTarget<'_>) -> bool {
        true
    }

    fn describe(&self) -> String {
        "всегда".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::target;

    struct Fixed(bool);

    impl Matcher for Fixed {
        fn matches(&self, _target: &MatchTarget<'_>) -> bool {
            self.0
        }
        fn describe(&self) -> String {
            format!("{}", self.0)
        }
    }

    fn yes() -> Box<dyn Matcher> {
        Box::new(Fixed(true))
    }

    fn no() -> Box<dyn Matcher> {
        Box::new(Fixed(false))
    }

    #[test]
    fn all_requires_every_condition() {
        let target = target();
        assert!(All(vec![yes(), yes()]).matches(&target));
        assert!(!All(vec![yes(), no()]).matches(&target));
    }

    #[test]
    fn any_requires_one_condition() {
        let target = target();
        assert!(Any(vec![no(), yes()]).matches(&target));
        assert!(!Any(vec![no(), no()]).matches(&target));
    }

    #[test]
    fn empty_sets_are_identities() {
        let target = target();
        assert!(All(vec![]).matches(&target));
        assert!(!Any(vec![]).matches(&target));
    }

    #[test]
    fn not_inverts() {
        let target = target();
        assert!(Not(no()).matches(&target));
        assert!(!Not(yes()).matches(&target));
    }

    #[test]
    fn nesting_works_to_any_depth() {
        let condition = Not(Box::new(All(vec![yes(), no()])));
        assert!(condition.matches(&target()));
    }

    #[test]
    fn description_reads_as_a_sentence() {
        let condition = All(vec![yes(), Box::new(Not(no()))]);
        assert_eq!(condition.describe(), "(true и не false)");
    }
}
