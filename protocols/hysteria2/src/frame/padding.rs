//! Случайное дополнение: скрывает предсказуемую длину кадров.
//! Границы взяты из эталонной реализации.

use penguin_proto::random;

/// Буквы и цифры: дополнение попадает в заголовок HTTP/3.
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
        let len = random::range(self.min as u64..self.max as u64 + 1) as usize;
        (0..len)
            .map(|_| char::from(ALPHABET[random::range(0..ALPHABET.len() as u64) as usize]))
            .collect()
    }
}

/// Наибольшая читаемая длина дополнения: потолок против гигантских объявлений.
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
