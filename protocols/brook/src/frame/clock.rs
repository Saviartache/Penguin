//! Текущее время в секундах Unix-эпохи — то, что уходит в метку кадра.
//!
//! Отдельная функция вместо `SystemTime::now()...expect(...)` в двух местах
//! ([`crate::outbound`] и [`crate::datagram`]) ради одного и того же выбора:
//! часы до 1970 года — это неисправная система, а не повод уронить
//! соединение вместе с ней.

use std::time::{SystemTime, UNIX_EPOCH};

/// Секунды с начала эпохи Unix.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_returns_a_plausible_recent_timestamp() {
        // Проверяем не точное время (тест не должен зависеть от часов
        // машины, на которой его запускают), а то, что функция вообще
        // отвечает разумным числом, а не нулём при живых часах.
        let now = now_unix();
        assert!(now > 1_700_000_000, "похоже на 1970 год, а не на текущий");
    }
}
