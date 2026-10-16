//! GREASE (RFC 8701): значения `0x?A?A`, как их выбирает BoringSSL
//! (uTLS `GetBoringGREASEValue`). У Firefox (NSS) GREASE нет.

use crate::rng::Rng;

/// Плейсхолдер GREASE в отпечатках до выбора конкретного значения.
pub const PLACEHOLDER: u16 = 0x0a0a;

/// Это GREASE-значение: оба байта равны, младшая тетрада `A`.
pub fn is_grease(value: u16) -> bool {
    (value >> 8) == (value & 0xff) && (value & 0x0f) == 0x0a
}

/// Пять независимых значений GREASE на один `ClientHello`.
#[derive(Debug, Clone, Copy)]
pub struct GreaseValues {
    /// Первый элемент списка шифров.
    pub cipher: u16,
    /// Первый элемент списка кривых и группа первой записи `key_share`.
    pub group: u16,
    /// Первое псевдорасширение (перед SNI, пустое тело).
    pub extension_first: u16,
    /// Второе псевдорасширение (перед `padding`, тело — один нулевой байт).
    pub extension_last: u16,
    /// Первый элемент `supported_versions`.
    pub version: u16,
}

impl GreaseValues {
    /// Тянет пять значений; при совпадении псевдорасширений второе сдвигается (`^ 0x1010`).
    pub fn from_rng(rng: &mut impl Rng) -> Self {
        let cipher = rng.next_u32() as u16;
        let group = rng.next_u32() as u16;
        let extension_first = rng.next_u32() as u16;
        let mut extension_last_seed = rng.next_u32() as u16;
        let version = rng.next_u32() as u16;

        if boring_value(extension_first) == boring_value(extension_last_seed) {
            extension_last_seed ^= 0x1010;
        }

        Self {
            cipher: boring_value(cipher),
            group: boring_value(group),
            extension_first: boring_value(extension_first),
            extension_last: boring_value(extension_last_seed),
            version: boring_value(version),
        }
    }
}

/// Сворачивает затравку в одно из шестнадцати значений `0x?A?A`.
fn boring_value(seed: u16) -> u16 {
    let byte = (seed & 0x00f0) | 0x0a;
    byte | (byte << 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::testing::StepRng;

    #[test]
    fn every_boring_value_is_recognized_as_grease() {
        for high in 0..16u16 {
            let seed = high << 4;
            let value = boring_value(seed);
            assert!(is_grease(value), "{value:#06x} не распознан как GREASE");
        }
    }

    #[test]
    fn a_placeholder_is_grease_and_a_real_cipher_is_not() {
        assert!(is_grease(PLACEHOLDER));
        assert!(!is_grease(0x1301), "TLS_AES_128_GCM_SHA256 — не GREASE");
        assert!(!is_grease(0x0a0b), "младшая тетрада должна быть ровно `A`");
    }

    #[test]
    fn colliding_extension_placeholders_are_forced_apart() {
        // Затравки 3 и 4 совпадают после свёртки (старшая тетрада 0x50).
        let mut seq = [0u16, 0, 0x0050, 0x0050, 0].into_iter();
        let mut rng = FakeRng(std::iter::from_fn(move || seq.next().map(u32::from)));
        let values = GreaseValues::from_rng(&mut rng);
        assert_ne!(
            values.extension_first, values.extension_last,
            "два псевдорасширения с одним значением не различить на проводе"
        );
    }

    #[test]
    fn all_five_roles_are_independent_in_practice() {
        let mut rng = StepRng::new(0x1234_5678, 0x9e37_79b9);
        let values = GreaseValues::from_rng(&mut rng);
        for value in [
            values.cipher,
            values.group,
            values.extension_first,
            values.extension_last,
            values.version,
        ] {
            assert!(is_grease(value));
        }
    }

    /// Отдаёт значения из заданной последовательности.
    struct FakeRng<I>(I);

    impl<I: Iterator<Item = u32>> Rng for FakeRng<I> {
        fn next_u32(&mut self) -> u32 {
            self.0.next().unwrap_or(0)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(4) {
                chunk.copy_from_slice(&self.next_u32().to_le_bytes()[..chunk.len()]);
            }
        }
    }
}
