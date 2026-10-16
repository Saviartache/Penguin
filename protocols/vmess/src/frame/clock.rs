//! Время Unix для опознавателя заголовка.

use std::time::{SystemTime, UNIX_EPOCH};

/// Секунды с начала эпохи; часы до 1970 дают 0, а не ошибку.
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
        assert!(now_unix() > 1_700_000_000);
    }
}
