//! Метка времени TAI64N: секунды TAI (8 байт, BE) и наносекунды (4 байта, BE).
//! Ответчик отклоняет рукопожатие с меткой не новее предыдущей (защита от повтора).

use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::constants::TIMESTAMP_LEN;

/// Эпоха TAI64: `2^62 + 10` (`base = 0x400000000000000a` в `wireguard-go/tai64n`).
const TAI64_BASE: u64 = (1u64 << 62) + 10;

/// Метка времени TAI64N.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tai64N {
    bytes: [u8; TIMESTAMP_LEN],
}

impl Tai64N {
    /// Текущее время; часы раньше 1970 года дают нулевые секунды (рукопожатие не пройдёт).
    pub fn now() -> Self {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self::from_unix(since_epoch.as_secs(), since_epoch.subsec_nanos())
    }

    /// Собирает метку из секунд и наносекунд Unix-времени.
    fn from_unix(unix_secs: u64, nanos: u32) -> Self {
        let mut bytes = [0u8; TIMESTAMP_LEN];
        bytes[0..8].copy_from_slice(&unix_secs.wrapping_add(TAI64_BASE).to_be_bytes());
        bytes[8..12].copy_from_slice(&nanos.to_be_bytes());
        Self { bytes }
    }

    /// Метка из готовых двенадцати байт.
    pub fn from_bytes(bytes: [u8; TIMESTAMP_LEN]) -> Self {
        Self { bytes }
    }

    /// Байты для `encrypted_timestamp` до шифрования.
    pub fn to_bytes(self) -> [u8; TIMESTAMP_LEN] {
        self.bytes
    }

    /// Строго новее другой: побайтово по BE (`After()` в `tai64n.go`).
    pub fn is_after(&self, other: &Self) -> bool {
        self.bytes > other.bytes
    }
}

/// Метка «раньше всех».
impl Default for Tai64N {
    fn default() -> Self {
        Self {
            bytes: [0u8; TIMESTAMP_LEN],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_base_matches_the_reference_hex_constant() {
        assert_eq!(TAI64_BASE, 0x400000000000000a);
    }

    #[test]
    fn a_later_timestamp_is_after_an_earlier_one() {
        let earlier = Tai64N::from_unix(1_700_000_000, 0);
        let later = Tai64N::from_unix(1_700_000_001, 0);
        assert!(later.is_after(&earlier));
        assert!(!earlier.is_after(&later));
    }

    #[test]
    fn nanoseconds_break_ties_within_the_same_second() {
        let earlier = Tai64N::from_unix(1_700_000_000, 100);
        let later = Tai64N::from_unix(1_700_000_000, 200);
        assert!(later.is_after(&earlier));
    }

    #[test]
    fn a_timestamp_is_never_after_itself() {
        let stamp = Tai64N::now();
        assert!(!stamp.is_after(&stamp));
    }

    #[test]
    fn the_default_is_older_than_any_real_clock() {
        let now = Tai64N::now();
        assert!(now.is_after(&Tai64N::default()));
    }

    #[test]
    fn the_wire_layout_is_big_endian_seconds_then_nanoseconds() {
        let stamp = Tai64N::from_unix(1, 2);
        let bytes = stamp.to_bytes();
        assert_eq!(&bytes[0..8], (1u64 + TAI64_BASE).to_be_bytes().as_slice());
        assert_eq!(&bytes[8..12], 2u32.to_be_bytes().as_slice());
    }
}
