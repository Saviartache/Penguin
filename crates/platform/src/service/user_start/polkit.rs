//! Правило polkit: пользователю окна разрешён только запуск юнита службы. Без обращений к ОС.

use crate::service::systemd::UNIT;

/// Каталог правил администратора; его читает polkit с версии 0.106.
pub(super) const RULES_DIR: &str = "/etc/polkit-1/rules.d";
pub(super) const RULE_PATH: &str = "/etc/polkit-1/rules.d/50-penguin.rules";

/// Текст правила; `None` — имя нельзя вставить в строку JavaScript как есть.
pub(super) fn rule_for(user: &str) -> Option<String> {
    let plain = !user.is_empty()
        && user
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '$'));
    plain.then(|| {
        format!(
            "// Penguin: {user} may start the tunnel service without a password.\n\
             polkit.addRule(function (action, subject) {{\n    \
                 if (action.id == \"org.freedesktop.systemd1.manage-units\" &&\n        \
                     action.lookup(\"unit\") == \"{UNIT}\" &&\n        \
                     action.lookup(\"verb\") == \"start\" &&\n        \
                     subject.user == \"{user}\") {{\n        \
                     return polkit.Result.YES;\n    \
                 }}\n\
             }});\n"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rule_grants_only_starting_our_unit_to_one_user() {
        let rule = rule_for("alice").expect("обычное имя");
        assert!(rule.contains("subject.user == \"alice\""), "{rule}");
        assert!(rule.contains("action.lookup(\"unit\") == \"penguin.service\""));
        assert!(rule.contains("action.lookup(\"verb\") == \"start\""));
        assert!(!rule.contains("stop"));
        assert!(RULE_PATH.starts_with(RULES_DIR));
    }

    #[test]
    fn a_name_that_could_break_the_script_is_refused() {
        for name in ["", "a\"b", "a\\b", "a\nb", "a b", "a'); //"] {
            assert!(rule_for(name).is_none(), "{name:?}");
        }
        assert!(rule_for("svc-user.1_$").is_some());
    }
}
