//! Разрешение конфликтов: приоритет, порядок, первое совпадение.
//!
//! Правило разбора одно и объяснимое:
//!
//! 1. правила сортируются по `priority`, при равенстве — по порядку в файле;
//! 2. первое совпавшее даёт решение, дальше не смотрим;
//! 3. не совпало ничего — умолчание режима.
//!
//! Именно первое совпадение, а не «самое точное». «Самое точное» невозможно
//! объяснить пользователю, глядя на список из тридцати правил: пришлось бы
//! сравнивать условия между собой и как-то решать, что `dest_port` точнее,
//! чем `process_name`. Порядок объясняется одной фразой и виден прямо в
//! интерфейсе.
//!
//! Сортировка обязана быть устойчивой: два правила с одинаковым приоритетом
//! должны остаться в том порядке, в каком их написал пользователь.

use super::rule::Rule;

/// Расставляет правила в порядке разбора.
pub fn sort(rules: &mut [Rule]) {
    // `sort_by_key`, а не `sort_unstable_by_key`: устойчивость здесь — часть
    // обещания, а не деталь реализации.
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
        // Пользователь расставил правила в файле; при равном приоритете
        // порядок обязан сохраниться, иначе разбор становится непредсказуемым.
        let mut rules = vec![rule("первое", 0), rule("второе", 0), rule("третье", 0)];
        sort(&mut rules);
        assert_eq!(ids(&rules), vec!["первое", "второе", "третье"]);
    }

    #[test]
    fn negative_priority_beats_everything() {
        // Так пишется правило «локальная сеть никогда не в тоннель»: оно
        // должно проверяться раньше всех остальных.
        let mut rules = vec![rule("обычное", 0), rule("локальная-сеть", -100)];
        sort(&mut rules);
        assert_eq!(ids(&rules)[0], "локальная-сеть");
    }
}
