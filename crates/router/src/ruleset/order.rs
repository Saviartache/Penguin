//! Порядок разбора: по `priority`, при равенстве — как в файле; решает первое
//! совпадение, не «самое точное».

use super::rule::Rule;

/// Расставляет правила в порядке разбора (сортировка устойчивая).
pub fn sort(rules: &mut [Rule]) {
    rules.sort_by_key(|rule| rule.priority);
}

#[cfg(test)]
mod tests {
    use penguin_core::id::RuleId;
    use penguin_match::logic::Always;

    use super::*;
    use crate::decision::Decision;

    fn rule(id: &str, priority: i32) -> Rule {
        Rule {
            id: RuleId::new(id),
            name: id.to_owned(),
            priority,
            condition: Box::new(Always),
            action: Decision::Direct,
        }
    }

    fn ids(rules: &[Rule]) -> Vec<String> {
        rules.iter().map(|r| r.id.to_string()).collect()
    }

    #[test]
    fn lower_priority_goes_first() {
        let mut rules = vec![rule("c", 10), rule("a", -5), rule("b", 0)];
        sort(&mut rules);
        assert_eq!(ids(&rules), vec!["a", "b", "c"]);
    }

    #[test]
    fn equal_priorities_keep_file_order() {
        let mut rules = vec![rule("первое", 0), rule("второе", 0), rule("третье", 0)];
        sort(&mut rules);
        assert_eq!(ids(&rules), vec!["первое", "второе", "третье"]);
    }

    #[test]
    fn negative_priority_beats_everything() {
        let mut rules = vec![rule("обычное", 0), rule("локальная-сеть", -100)];
        sort(&mut rules);
        assert_eq!(ids(&rules)[0], "локальная-сеть");
    }
}
