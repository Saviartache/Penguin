//! Режим DPI — описание формы.

use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Стратегии, которые принимает режим (список `penguin_dpi`): остальные шлют
/// ложное приветствие, а принимать его некому. `multisplit` первым: не добавляет
/// пакетов, а `disorder` зависит от TTL оборудования провайдера.
const DESYNC: &[&str] = &["multisplit", "disorder"];

/// Поле одно: сервера нет, соединение идёт прямо к сайту. Точки разреза, TTL и
/// пауза — в файле настроек.
static FIELDS: &[FieldSpec] = &[FieldSpec::choice(
    "desync",
    &["desync", "strategy"],
    |s| s.desync_strategy,
    DESYNC,
)];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "dpi",
    label: "DPI",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
    // Единственное направление без тоннеля: молчать об этом нельзя.
    note: Some(|s| s.dpi_no_tunnel),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_says_out_loud_that_there_is_no_tunnel() {
        assert!(SPEC.note.is_some());
    }

    #[test]
    fn there_is_no_address_to_ask_for() {
        assert!(FIELDS.iter().all(|field| field.key != "server"));
    }

    #[test]
    fn a_new_profile_already_bypasses_something() {
        let desync = FIELDS
            .iter()
            .find(|field| field.key == "desync")
            .expect("поле есть");
        assert_eq!(desync.default_text(), "multisplit");
    }

    #[test]
    fn only_the_strategies_the_mode_accepts_are_offered() {
        assert_eq!(DESYNC, ["multisplit", "disorder"]);
    }
}
