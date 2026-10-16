//! Источник случайности сборщика; в тестах подменяется детерминированным.

use penguin_proto::random;

/// Источник случайных чисел и байтов.
pub trait Rng {
    /// Следующее 32-битное число.
    fn next_u32(&mut self) -> u32;

    /// Заполняет буфер байтами.
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

/// Системный источник: байты криптостойкие.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRng;

impl Rng for SystemRng {
    fn next_u32(&mut self) -> u32 {
        random::u64() as u32
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        random::fill(dest);
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::Rng;

    /// Арифметическая прогрессия: `initial`, `initial + step`, ...
    pub(crate) struct StepRng {
        value: u64,
        step: u64,
    }

    impl StepRng {
        pub(crate) fn new(initial: u64, step: u64) -> Self {
            Self {
                value: initial,
                step,
            }
        }

        fn next_u64(&mut self) -> u64 {
            let out = self.value;
            self.value = self.value.wrapping_add(self.step);
            out
        }
    }

    impl Rng for StepRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
            }
        }
    }

    /// splitmix64 с заданным зерном.
    pub(crate) struct SeededRng(pub(crate) u64);

    impl Rng for SeededRng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (z ^ (z >> 31)) as u32
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(4) {
                chunk.copy_from_slice(&self.next_u32().to_le_bytes()[..chunk.len()]);
            }
        }
    }
}
