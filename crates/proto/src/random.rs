//! Случайность: криптостойкая из ОС и быстрая для паддинга и джиттера.

use std::cell::Cell;
use std::ops::Range;

thread_local! {
    static STATE: Cell<u64> = Cell::new(os_u64());
}

/// Заполняет буфер криптостойкими байтами ОС: ключи, нонсы, соли.
///
/// Паникует, если у ОС нет источника энтропии: работать без него нельзя.
pub fn fill(buf: &mut [u8]) {
    if let Err(e) = getrandom::fill(buf) {
        panic!("источник энтропии ОС недоступен: {e}");
    }
}

/// Массив криптостойких байтов.
pub fn array<const N: usize>() -> [u8; N] {
    let mut buf = [0; N];
    fill(&mut buf);
    buf
}

/// Быстрое некриптостойкое число (wyrand): длины паддинга, порядок, джиттер.
pub fn u64() -> u64 {
    STATE.with(|state| {
        let x = state.get().wrapping_add(0xa076_1d64_78bd_642f);
        state.set(x);
        let t = u128::from(x) * u128::from(x ^ 0xe703_7ed1_a0b4_28db);
        (t as u64) ^ ((t >> 64) as u64)
    })
}

/// Быстрое некриптостойкое число из `[start, end)`; пустой диапазон даёт `start`.
pub fn range(range: Range<u64>) -> u64 {
    let span = range.end.saturating_sub(range.start);
    // Умножение Лемира: без деления и без заметного смещения.
    range.start + ((u128::from(u64()) * u128::from(span)) >> 64) as u64
}

fn os_u64() -> u64 {
    u64::from_ne_bytes(array())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_stays_inside() {
        for _ in 0..10_000 {
            let v = range(10..20);
            assert!((10..20).contains(&v));
        }
        assert_eq!(range(5..5), 5);
    }

    #[test]
    fn fill_is_not_constant() {
        assert_ne!(array::<32>(), [0; 32]);
        assert_ne!(u64(), u64());
    }
}
