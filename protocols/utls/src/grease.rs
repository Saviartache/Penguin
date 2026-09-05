//! GREASE (RFC 8701) — значения-пустышки, которыми Chrome и Safari (оба на
//! BoringSSL) забивают списки шифров, кривых и версий, чтобы сервер, упавший
//! на незнакомом значении, был виден заранее, а не в день, когда в TLS
//! добавят что-то новое. Firefox этого не делает вовсе: у NSS своей GREASE
//! нет, и её отсутствие — тоже часть отпечатка, а не недосмотр.
//!
//! # Как именно выбирается значение
//!
//! Годится 16 значений вида `0x?A?A`, где `?` — одна и та же тетрада в обоих
//! байтах: `0x0A0A`, `0x1A1A`, ..., `0xFAFA`. BoringSSL берёт для этого не
//! шестнадцать вариантов честного броска, а старший полубайт случайного
//! байта (см. `ssl/internal.h` в BoringSSL и `GetBoringGREASEValue` в uTLS,
//! `u_tls_extensions.go`): случайное значение маскируется до одной тетрады,
//! к ней приписывается `0xA`, и результат дублируется в оба байта.
//!
//! # Пять ролей, одна на каждое место GREASE в `ClientHello`
//!
//! У BoringSSL GREASE не одно число на весь `ClientHello`, а пять
//! независимых: список шифров, список кривых (то же значение — и в
//! `key_share`, это не совпадение, обе группы говорят об одном), первое
//! псевдорасширение (перед SNI, с пустым телом), второе псевдорасширение
//! (последним перед padding, с телом в один нулевой байт) и список версий.
//! Если оба псевдорасширения случайно совпали — а на 16 вариантах это каждый
//! шестнадцатый ClientHello, — BoringSSL меняет второе, а не бросает кости
//! заново: `seed ^= 0x1010` гарантированно сдвигает его тетраду на другое
//! значение.

use rand::RngCore;

/// Плейсхолдер GREASE в отпечатках, где значение ещё не выбрано конкретно
/// (`SupportedCurvesExtension`, `KeyShareExtension` и так далее у uTLS перед
/// тем, как `ApplyPreset` пройдётся по списку и заменит его на настоящее).
pub const PLACEHOLDER: u16 = 0x0a0a;

/// Это GREASE-значение — то есть оба байта одинаковы, а младшая тетрада — `A`.
pub fn is_grease(value: u16) -> bool {
    (value >> 8) == (value & 0xff) && (value & 0x0f) == 0x0a
}

/// Пять значений GREASE на один `ClientHello`, по одному на каждую роль.
///
/// Роли не смешиваются: список шифров и список кривых видны серверу порознь,
/// и настоящий браузер не обязан (и обычно не станет) ставить в них одно и то
/// же число.
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
    /// Тянет пять независимых значений из генератора.
    ///
    /// Повторяет процедуру BoringSSL один в один: раздельные случайные
    /// затравки, раздельная свёртка каждой в `0x?A?A`, и разбор двух
    /// псевдорасширений, если им выпало одно и то же число.
    pub fn from_rng(rng: &mut impl RngCore) -> Self {
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

/// Сворачивает случайный байт в одно из шестнадцати значений `0x?A?A`.
///
/// `seed & 0x00f0` берёт старшую тетраду младшего байта — только её,
/// остальные 12 бит роли не играют. `| 0x0a` фиксирует младшую тетраду.
/// Дублирование в верхний байт — то самое повторение, по которому GREASE и
/// узнаётся: `is_grease` проверяет именно его.
fn boring_value(seed: u16) -> u16 {
    let byte = (seed & 0x00f0) | 0x0a;
    byte | (byte << 8)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Третья и четвёртая затравки (`extension_first`, `extension_last`)
        // специально выбраны так, чтобы совпасть после свёртки: старшая
        // тетрада младшего байта у обеих равна 0x50.
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
        // Не строгое доказательство, а сигнал тревоги: если однажды роли
        // случайно схлопнутся в одно значение генератора, тест это заметит.
        let mut rng = rand::rngs::mock::StepRng::new(0x1234_5678, 0x9e37_79b9);
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

    /// Заглушка `RngCore`, отдающая значения из заранее заданной
    /// последовательности, — нужна ровно один раз, чтобы воспроизвести
    /// столкновение двух псевдорасширений детерминированно.
    struct FakeRng<I>(I);

    impl<I: Iterator<Item = u32>> RngCore for FakeRng<I> {
        fn next_u32(&mut self) -> u32 {
            self.0.next().unwrap_or(0)
        }

        fn next_u64(&mut self) -> u64 {
            u64::from(self.next_u32())
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(4) {
                chunk.copy_from_slice(&self.next_u32().to_le_bytes()[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
}
