//! Общее у заголовков TCP и UDP Shadowsocks 2022: тип стороны, метка времени, дополнение.
//!
//! Эталон: `shadowsocks-rust` (`SERVER_STREAM_TIMESTAMP_MAX_DIFF = 30`,
//! `MAX_PADDING_SIZE = 900`), `sing-shadowsocks2` (`MaxPaddingLength = 900`, `diff > 30`).

use penguin_proto::random;

use crate::error::{ShadowsocksError, ShadowsocksResult};

/// Заголовок отправлен клиентом.
pub const TYPE_CLIENT: u8 = 0;
/// Заголовок отправлен сервером.
pub const TYPE_SERVER: u8 = 1;

/// Наибольшая длина случайного дополнения.
pub const MAX_PADDING: u16 = 900;

/// Наибольшее расхождение метки времени с часами машины.
const MAX_TIMESTAMP_DIFF_SECS: u64 = 30;

/// Текущее время в секундах от эпохи Unix; часы до 1970 дают 0, а не панику.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Проверяет метку времени собеседника; ошибка называет расхождение часов.
pub fn check_timestamp(theirs: u64, now: u64) -> ShadowsocksResult<()> {
    let diff = now.abs_diff(theirs);
    if diff > MAX_TIMESTAMP_DIFF_SECS {
        return Err(ShadowsocksError::ClockSkew(diff));
    }
    Ok(())
}

/// Длина дополнения: только при пустой нагрузке, как в `shadowsocks-rust`.
pub fn padding_len(payload_is_empty: bool) -> u16 {
    if payload_is_empty {
        random::range(0..u64::from(MAX_PADDING) + 1) as u16
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timestamp_within_range_is_accepted() {
        check_timestamp(1_000, 1_010).expect("10 секунд — в пределах");
        check_timestamp(1_010, 1_000).expect("тоже в пределах, другая сторона");
        check_timestamp(1_000, 1_030).expect("30 секунд — ровно предел");
    }

    #[test]
    fn a_timestamp_too_far_off_names_the_skew_in_seconds() {
        let err = check_timestamp(1_000, 1_100).expect_err("100 секунд — не по протоколу");
        let text = err.to_string();
        assert!(text.contains("100"), "{text}");
        assert!(text.to_lowercase().contains("час"), "{text}");
    }

    #[test]
    fn padding_is_only_added_to_an_empty_frame() {
        assert_eq!(padding_len(false), 0);
        for _ in 0..50 {
            assert!(padding_len(true) <= MAX_PADDING);
        }
    }

    #[test]
    fn now_unix_looks_like_the_present_and_not_1970() {
        assert!(
            now_unix() > 1_700_000_000,
            "часы машины выглядят неисправными"
        );
    }
}
