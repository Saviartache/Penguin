//! Режим DPI — описание формы.

use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Чем ломается сборка потока у DPI.
///
/// Их две, а не пять: остальные три шлют ложное приветствие, а принял бы его
/// здесь сам сайт — своего сервера у этого режима нет. Отвергает их сам
/// протокол (`penguin_dpi`), и список тут повторяет его список намеренно:
/// показать в форме выбор, который на сохранении отвергнут, — худший способ
/// об этом сообщить.
///
/// `multisplit` первым: разрез не добавляет ни одного лишнего пакета, а
/// `disorder` полагается на малый TTL, то есть на то, каким по счёту стоит
/// оборудование провайдера.
const DESYNC: &[&str] = &["multisplit", "disorder"];

/// Поля формы.
///
/// Одно. Адреса здесь нет и быть не может: сервера у этого режима нет вовсе —
/// соединение идёт прямо к сайту. Точки разреза, TTL и пауза настраиваются в
/// файле, как и у `pingwin`: у поля выбора нет пустого значения, а список
/// строк форма показать не умеет.
static FIELDS: &[FieldSpec] = &[FieldSpec::choice(
    "desync",
    &["desync", "strategy"],
    |s| s.desync_strategy,
    DESYNC,
)];

/// Описание протокола.
///
/// Подпись не переводится, как и у остальных: три буквы одинаковы на любом
/// языке, а что за ними — говорит строка над формой.
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
        // Профиль в общем списке выглядит как остальные, а трафик через него
        // идёт открытым и прямо к сайту. Узнать об этом надо до подключения.
        assert!(SPEC.note.is_some());
    }

    #[test]
    fn there_is_no_address_to_ask_for() {
        assert!(FIELDS.iter().all(|field| field.key != "server"));
    }

    #[test]
    fn a_new_profile_already_bypasses_something() {
        // Умолчание «ничего не делать» превратило бы режим в обычное прямое
        // соединение с лишним именем в списке.
        let desync = FIELDS
            .iter()
            .find(|field| field.key == "desync")
            .expect("поле есть");
        assert_eq!(desync.default_text(), "multisplit");
    }

    #[test]
    fn only_the_strategies_the_mode_accepts_are_offered() {
        // Опечатка или лишнее имя здесь означали бы профиль, который
        // сохраняется и не подключается.
        assert_eq!(DESYNC, ["multisplit", "disorder"]);
    }
}
