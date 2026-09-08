//! Текущее время в секундах Unix-эпохи — то, что уходит в опознаватель
//! заголовка ([`crate::crypto::auth_id`]).
//!
//! Тот же выбор, что и у Brook (`protocols/brook/src/frame/clock.rs`): часы
//! до 1970 года — это неисправная система, а не повод уронить соединение.

use std::time::{SystemTime, UNIX_EPOCH};

/// Секунды с начала эпохи Unix.
///
/// `i64`, а не `u64`: опознаватель заголовка пишет метку времени именно этим
/// типом (`CreateAuthID(cmdKey []byte, time int64)`, эталон), и часы, разумно
/// настроенные, никогда не приблизятся к его пределу.
pub fn now_unix() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    i64::try_from(secs).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_returns_a_plausible_recent_timestamp() {
        assert!(
            now_unix() > 1_700_000_000,
            "похоже на 1970 год, а не на текущий"
        );
    }
}
