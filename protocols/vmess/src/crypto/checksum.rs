//! CRC32 (IEEE) и FNV-1a (32 бита) без внешней зависимости.

/// Полином CRC32 (IEEE 802.3) в отражённом виде.
const CRC32_POLY: u32 = 0xEDB8_8320;

/// CRC32 (IEEE) от среза; входит в опознаватель заголовка.
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

/// FNV-1a (32 бита) от среза; контрольная сумма заголовка запроса.
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
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc32_of_empty_input_is_zero() {
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn fnv1a_matches_the_well_known_check_value() {
        assert_eq!(fnv1a(b""), FNV_OFFSET);
        assert_eq!(fnv1a(b"a"), 0xe40c_292c);
    }
}
