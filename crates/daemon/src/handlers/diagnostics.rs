//! Диагностика: утечки, маршруты, состояние адаптера.
//!
//! Отвечает на вопрос «почему не работает», который пользователь задаёт чаще
//! всех остальных. Проверки идут снизу вверх — от того, что должно быть на
//! месте всегда, к тому, что нужно только тоннелю.

use serde::Serialize;

/// Что удалось выяснить о системе.
#[derive(Debug, Clone, Serialize)]
pub struct Diagnostics {
    /// Есть ли права на тоннель.
    pub elevated: bool,
    /// Через какой интерфейс машина выходит наружу.
    pub default_interface: Option<u32>,
    /// Адрес этого интерфейса — к нему привязывается прямой выход.
    pub default_address: Option<String>,
    /// Состояние службы.
    pub service: String,
}

/// Собирает диагностику.
pub fn collect() -> Diagnostics {
    let route = penguin_platform::default_route().ok();

    Diagnostics {
        elevated: penguin_platform::is_elevated(),
        default_interface: route.as_ref().map(|route| route.interface_index),
        default_address: route.as_ref().map(|route| route.address.to_string()),
        service: penguin_platform::service::status()
            .map(|status| status.as_str().to_owned())
            .unwrap_or_else(|_| "неизвестно".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collecting_never_panics() {
        // Диагностику запускают именно тогда, когда что-то сломано: упасть на
        // ней — худшее, что можно сделать.
        let diagnostics = collect();
        assert!(!diagnostics.service.is_empty());
    }

    #[test]
    fn serializes_for_the_wire() {
        serde_json::to_string(&collect()).expect("сериализуется");
    }
}
