//! Общее у заголовков TCP и UDP протокола Shadowsocks 2022: тип стороны,
//! метка времени, дополнение длины.
//!
//! Числа отсюда — часть договора с сервером, а не наш выбор. Тридцать секунд
//! и девятьсот байт названы в `shadowsocks-rust`
//! (`crates/shadowsocks/src/relay/tcprelay/proxy_stream/protocol/v2.rs`:
//! `SERVER_STREAM_TIMESTAMP_MAX_DIFF = 30`, `MAX_PADDING_SIZE = 900`;
//! `relay/udprelay/aead_2022.rs`: `SERVER_PACKET_TIMESTAMP_MAX_DIFF = 30`) и
//! независимо в `sing-shadowsocks2`
//! (`shadowaead_2022/protocol.go`: `MaxPaddingLength = 900`, `method.go`:
//! `if diff > 30`).

use rand::Rng;

use crate::error::{ShadowsocksError, ShadowsocksResult};

/// Заголовок отправлен клиентом.
pub const TYPE_CLIENT: u8 = 0;
/// Заголовок отправлен сервером.
pub const TYPE_SERVER: u8 = 1;

/// Наибольшая длина случайного дополнения.
pub const MAX_PADDING: u16 = 900;

/// Наибольшее расхождение метки времени с часами машины.
const MAX_TIMESTAMP_DIFF_SECS: u64 = 30;

/// Текущее время в секундах от эпохи Unix.
///
/// `unwrap_or` вместо `expect`: часы до 1970 года не бывают на практике, но
/// падать на пути соединения нельзя ни при каком вводе (`AGENTS.md` §4.3) —
/// нулевая метка в этом случае просто не пройдёт проверку сервера, и это не
/// хуже паники.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Проверяет метку времени из заголовка собеседника.
///
/// `Err` называет расхождение прямо: рассинхронизация часов этой машины —
/// частая причина, из-за которой сервер молча закрывает соединение, и без
/// явного текста её ищут в сети, а не в `date`.
pub fn check_timestamp(theirs: u64, now: u64) -> ShadowsocksResult<()> {
    let diff = now.abs_diff(theirs);
    if diff > MAX_TIMESTAMP_DIFF_SECS {
        return Err(ShadowsocksError::ClockSkew(diff));
    }
    Ok(())
}

/// Длина случайного дополнения.
///
/// Дополнение имеет смысл только тогда, когда полезной нагрузки в кадре ещё
/// нет: кадр без него был бы всегда одной и той же длины, и по ней его легко
/// выделить в трафике. Ровно так же решает и `shadowsocks-rust`
/// (`get_aead_2022_padding_size`: дополнение только при пустом `payload`).
pub fn padding_len(payload_is_empty: bool) -> u16 {
    if payload_is_empty {
        rand::thread_rng().gen_range(0..=MAX_PADDING)
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
