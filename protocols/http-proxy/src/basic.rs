//! Пароль в заголовке `Proxy-Authorization` (RFC 7617).
//!
//! `Basic` — это `имя:пароль`, закодированные base64. Не зашифрованные:
//! раскодировать их обратно может кто угодно, кто видел заголовок. Отсюда и
//! разделение протоколов в [`crate`]: через `http` пароль уходит по сети
//! читаемым, через `https` — внутри TLS.
//!
//! Кодировщик здесь свой, на два десятка строк. Отдельная зависимость ради
//! одной таблицы из 64 знаков означала бы ещё один крейт в графе клиента, за
//! которым надо следить.

/// Знаки base64 в стандартном порядке (RFC 4648).
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Кодирует байты в base64 с дополнением.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        // Три байта складываются в одно число и разбираются по шесть бит:
        // недостающие байты считаются нулями, а их место в конце занимает `=`.
        let mut block = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            block |= u32::from(*byte) << (16 - 8 * index);
        }

        for slot in 0..4 {
            if slot <= chunk.len() {
                let index = (block >> (18 - 6 * slot)) & 0b11_1111;
                out.push(char::from(ALPHABET[index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Значение заголовка `Proxy-Authorization` целиком.
pub fn header_value(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        encode(format!("{username}:{password}").as_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_examples_from_the_rfc() {
        // Проверять кодировщик надо чужими ответами, а не своими: ошибка,
        // повторённая в тесте, выглядит как успех.
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn the_classic_example_of_the_header() {
        // `Aladdin:open sesame` из RFC 7617.
        assert_eq!(
            header_value("Aladdin", "open sesame"),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn a_password_with_non_ascii_survives() {
        // Пароль на русском встречается; кодируется он байтами UTF-8, а не
        // знаками, и обрезать его нельзя.
        let value = header_value("пользователь", "пароль");
        assert!(value.starts_with("Basic "));
        assert!(value.len() > "Basic ".len());
    }

    #[test]
    fn every_length_ends_up_a_multiple_of_four() {
        // Дополнение `=` — часть записи: без него принимающая сторона вправе
        // отвергнуть заголовок целиком.
        for len in 0..32 {
            let encoded = encode(&vec![b'x'; len]);
            assert_eq!(encoded.len() % 4, 0, "длина {len} даёт `{encoded}`");
        }
    }
}
