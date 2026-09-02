//! Случайное дополнение — часть маскировки, а не украшение.
//!
//! Без него запрос на соединение имеет длину, однозначно вычислимую из длины
//! адреса, и весь поток превращается в набор кадров предсказуемого размера.
//! Наблюдателю этого достаточно: сама последовательность длин выдаёт прокси,
//! даже если содержимое зашифровано.
//!
//! Границы взяты из эталонной реализации: они часть протокола ровно в той же
//! мере, что и номера кадров, — сервер полагается на то, что дополнение
//! умещается в отведённые ему пределы.

use rand::Rng;

/// Символы, из которых набирается дополнение.
///
/// Только буквы и цифры: дополнение попадает в том числе в заголовок HTTP/3
/// при аутентификации, а туда произвольные байты класть нельзя.
const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Диапазон длин дополнения.
#[derive(Debug, Clone, Copy)]
pub struct Padding {
    /// Наименьшая длина.
    pub min: usize,
    /// Наибольшая длина.
    pub max: usize,
}

impl Padding {
    /// Дополнение запроса аутентификации.
    pub const AUTH_REQUEST: Self = Self {
        min: 256,
        max: 2048,
    };
    /// Дополнение ответа на аутентификацию.
    pub const AUTH_RESPONSE: Self = Self {
        min: 256,
        max: 2048,
    };
    /// Дополнение запроса на TCP-соединение.
    pub const TCP_REQUEST: Self = Self { min: 64, max: 512 };
    /// Дополнение ответа на запрос TCP-соединения.
    pub const TCP_RESPONSE: Self = Self {
        min: 128,
        max: 1024,
    };

    /// Набирает дополнение случайной длины из этого диапазона.
    pub fn generate(&self) -> String {
        let mut rng = rand::thread_rng();
        let len = rng.gen_range(self.min..=self.max);
        (0..len)
            .map(|_| {
                let index = rng.gen_range(0..ALPHABET.len());
                char::from(ALPHABET[index])
            })
            .collect()
    }
}

/// Наибольшая длина дополнения, которую мы согласны прочитать.
///
/// Не про эстетику: без потолка сторона на том конце объявляет дополнение
/// длиной в четыре гигабайта, и мы честно выделяем под него память.
pub const MAX_PADDING_LENGTH: u64 = 4096;

/// Наибольшая длина адреса.
pub const MAX_ADDRESS_LENGTH: u64 = 2048;

/// Наибольшая длина текстового сообщения в ответе.
pub const MAX_MESSAGE_LENGTH: u64 = 2048;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stays_within_bounds() {
        let padding = Padding { min: 10, max: 20 };
        for _ in 0..100 {
            let generated = padding.generate();
            assert!((10..=20).contains(&generated.len()));
            assert!(generated.bytes().all(|b| ALPHABET.contains(&b)));
        }
    }

    #[test]
    fn length_varies() {
        // Дополнение постоянной длины не скрывает ничего: если бы длина не
        // менялась, кадры снова стали бы предсказуемыми.
        let lengths: std::collections::HashSet<usize> = (0..50)
            .map(|_| Padding::TCP_REQUEST.generate().len())
            .collect();
        assert!(lengths.len() > 1);
    }

    #[test]
    fn single_length_range_works() {
        let padding = Padding { min: 7, max: 7 };
        assert_eq!(padding.generate().len(), 7);
    }
}
