//! Метка времени TAI64N: двенадцать байт, которые не позволяют переслать
//! старое рукопожатие заново.
//!
//! ```text
//! ┌───────────────────────┬──────────────────┐
//! │ секунды TAI (8, BE)    │ наносекунды (4, BE) │
//! └───────────────────────┴──────────────────┘
//! ```
//!
//! Секунды — не Unix-время напрямую, а Unix-время плюс метка эпохи TAI64:
//! `2^62 + 10`. Ответчик хранит наибольшую метку, полученную от этого
//! клиента, и отклоняет рукопожатие, если новая метка не строго больше —
//! иначе перехваченное первое сообщение рукопожатия можно переслать снова
//! и получить тот же ответ (реплей-атака на само рукопожатие, а не на
//! пакеты данных — от тех защищает [`crate::crypto::replay`]).
//!
//! Абсолютная точность TAI (с учётом отличия от UTC на количество
//! введённых секунд координации) протоколу не важна: сравнение — только
//! между метками одного клиента, а не с настоящим временем сервера.
//! Значение эпохи важно лишь тем, что оно совпадает у всех реализаций,
//! иначе конкатенация «секунды после сложения с эпохой» перестанет быть
//! монотонной с самим Unix-временем и почти-корректный клиент начнёт
//! слать метки то больше, то меньше настоящего хода часов.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::constants::TIMESTAMP_LEN;

/// Эпоха TAI64: `2^62` (метка формата TAI64) плюс 10 — секунды координации,
/// которые были накоплены к 1972 году, когда была принята TAI64.
///
/// Источник: `tai64n.go` в `wireguard-go` (`golang.zx2c4.com/wireguard/tai64n`,
/// импортируется из `device/noise-protocol.go`), константа
/// `base = uint64(0x400000000000000a)`. Значение проверено независимо:
/// `0x400000000000000a == (1u64 << 62) + 10` — тест ниже.
const TAI64_BASE: u64 = (1u64 << 62) + 10;

/// Метка времени TAI64N.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tai64N {
    bytes: [u8; TIMESTAMP_LEN],
}

impl Tai64N {
    /// Текущее время.
    ///
    /// `SystemTime::now()` до `UNIX_EPOCH` не бывает на нормально
    /// настроенной системе; если часы всё же выставлены раньше 1970 года,
    /// берётся нулевая метка — рукопожатие с ней просто не пройдёт (ответчик
    /// увидит её не больше предыдущей), а не паникует здесь.
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

    /// Метка из уже готовых двенадцати байт — так, как она приходит
    /// расшифрованной с провода.
    pub fn from_bytes(bytes: [u8; TIMESTAMP_LEN]) -> Self {
        Self { bytes }
    }

    /// Байты, которые уходят в поле `encrypted_timestamp` до шифрования.
    pub fn to_bytes(self) -> [u8; TIMESTAMP_LEN] {
        self.bytes
    }

    /// Метка строго новее другой.
    ///
    /// Сравнение — побайтовое по big-endian записи, что для этого формата
    /// совпадает с числовым: секунды старше наносекунд лексикографически
    /// ровно так же, как и по значению. Источник: `After()` в `tai64n.go`
    /// (`bytes.Compare(t1[:], t2[:]) > 0`).
    pub fn is_after(&self, other: &Self) -> bool {
        self.bytes > other.bytes
    }
}

/// Метка «раньше всех» — с ней принимается первое рукопожатие от клиента:
/// любая настоящая метка окажется новее.
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
        // Захардкоженное шестнадцатеричное значение из `wireguard-go`,
        // сверено побайтово, а не подобрано под формулу ниже.
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
        // Не строгое неравенство означало бы, что рукопожатие можно
        // переслать заново с той же меткой и получить тот же ответ.
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
