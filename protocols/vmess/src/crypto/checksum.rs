//! CRC32 и FNV-1a — оба нужны голыми, без внешней зависимости.
//!
//! Оба — открытые, никем не подкрученные под протокол алгоритмы (IEEE 802.3
//! и `hash/fnv` из стандартной библиотеки Go), а не то, что стоило бы сверять
//! с эталоном байт в байт: правильность здесь проверяется тестами на
//! опубликованные контрольные значения этих же алгоритмов, а не на что-то
//! специфичное для VMess. Заводить ради двадцати строк ещё одну зависимость,
//! которая и так уже случайно затянута транзитивно, смысла нет.
//!
//! - CRC32 (IEEE, полином `0xEDB88320`, отражённый, начальное и финальное
//!   значение — все единицы) — часть опознавателя заголовка ([`crate::crypto::auth_id`]).
//! - FNV-1a (32 бита, основание `0x811c9dc5`, множитель `0x01000193`) —
//!   контрольная сумма заголовка запроса ([`crate::frame::request`]).

/// Полином CRC32 (IEEE 802.3) в отражённом виде.
const CRC32_POLY: u32 = 0xEDB8_8320;

/// CRC32 (IEEE) от среза.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (CRC32_POLY & mask);
        }
    }
    !crc
}

/// Основание FNV-1a (32 бита).
const FNV_OFFSET: u32 = 0x811c_9dc5;
/// Множитель FNV-1a (32 бита).
const FNV_PRIME: u32 = 0x0100_0193;

/// FNV-1a (32 бита) от среза.
pub fn fnv1a(data: &[u8]) -> u32 {
    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_well_known_check_value() {
        // Контрольное значение CRC32 (IEEE) для строки "123456789" — общее
        // место во всех описаниях алгоритма, не что-то из VMess.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc32_of_empty_input_is_zero() {
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn fnv1a_matches_the_well_known_check_value() {
        // FNV-1a 32 бита от пустой строки — основание без единого умножения.
        assert_eq!(fnv1a(b""), FNV_OFFSET);
        // FNV-1a 32 бита от "a" — опубликованное контрольное значение.
        assert_eq!(fnv1a(b"a"), 0xe40c_292c);
    }
}
