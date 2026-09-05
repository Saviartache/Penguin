//! Кадр четвёртой версии: заголовок, дополнение, обмен байтами.
//!
//! ```text
//!  [соль 16] [заголовок 7+16] [дополнение] [данные+16]
//!             ^^^^^^^^^^^^^^^                ^^^^^^^^
//!             зашифрован своим шагом счётчика, как и данные
//! ```
//!
//! Заголовок в открытом виде — семь байт:
//!
//! ```text
//!  [4][0][0][длина дополнения 2 BE][длина данных 2 BE]
//! ```
//!
//! # Обмен байтами
//!
//! Перед отправкой чётные байты дополнения меняются местами с чётными
//! байтами зашифрованных данных ([`swap`]). Смысла в этом для стойкости нет
//! — данные уже закрыты меткой, — но собеседник делает обратное, и пропустить
//! этот шаг значит отдать серверу мусор вместо данных. Действие обратно само
//! себе: применённое дважды, оно ничего не меняет.
//!
//! # Откуда всё это
//!
//! Из одной реализации. Разбор протокола, по которому написаны остальные,
//! четвёртой версии не касается вовсе, а вторая известная реализация — копия
//! первой. Проверить это, кроме как о живой сервер, нечем.

use rand::Rng;

/// Длина соли.
pub const SALT_LEN: usize = 16;

/// Длина заголовка в открытом виде.
pub const HEADER_LEN: usize = 7;

/// Первый байт заголовка. Он же и есть «четвёртая версия кадра».
pub const HEADER_MARK: u8 = 4;

/// Наибольшая длина данных и дополнения в одном кадре.
pub const MAX_PAYLOAD: usize = 0x3FFF;

/// Размер, вокруг которого пляшут пределы кадра.
///
/// Это обычный MTU минус заголовки: кадр, уложившийся в него, уходит одним
/// пакетом. Число взято у эталона.
pub const FRAME_SIZE: usize = 1460;

/// Наименьшее дополнение первого кадра.
pub const INITIAL_PADDING_MIN: u16 = 0x100;

/// Насколько оно может быть больше наименьшего.
pub const INITIAL_PADDING_SPAN: u16 = 0x100;

/// Что сказано в заголовке кадра.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Сколько байт дополнения идёт перед данными.
    pub padding: usize,
    /// Сколько байт данных в кадре.
    pub payload: usize,
}

/// Собирает заголовок в открытом виде.
pub fn header(padding: usize, payload: usize) -> [u8; HEADER_LEN] {
    let padding = (padding.min(MAX_PAYLOAD) as u16).to_be_bytes();
    let payload = (payload.min(MAX_PAYLOAD) as u16).to_be_bytes();
    [
        HEADER_MARK,
        0,
        0,
        padding[0],
        padding[1],
        payload[0],
        payload[1],
    ]
}

/// Разбирает заголовок. `None` — это не кадр четвёртой версии.
pub fn parse(plain: &[u8]) -> Option<Header> {
    let plain: &[u8; HEADER_LEN] = plain.first_chunk()?;
    if plain.len() != HEADER_LEN || plain[0] != HEADER_MARK {
        return None;
    }

    let padding = usize::from(u16::from_be_bytes([plain[3], plain[4]]));
    let payload = usize::from(u16::from_be_bytes([plain[5], plain[6]]));
    if padding > MAX_PAYLOAD || payload > MAX_PAYLOAD {
        return None;
    }
    Some(Header { padding, payload })
}

/// Меняет местами чётные байты дополнения и зашифрованных данных.
///
/// Обратно само себе: применённое дважды, ничего не меняет. На этом и держится
/// разбор — тот, кто читает, зовёт его на тех же двух кусках.
pub fn swap(padding: &mut [u8], payload: &mut [u8]) {
    let limit = padding.len().min(payload.len());
    let mut at = 0;
    while at < limit {
        std::mem::swap(&mut padding[at], &mut payload[at]);
        at += 2;
    }
}

/// Выбирает байты дополнения.
///
/// Не случайные: они подбираются так, чтобы доля единичных бит во всём кадре
/// попала в нужный промежуток. Зачем это нужно, эталон не объясняет; похоже
/// на попытку не выделяться среди тех, кто смотрит на распределение бит.
/// Сервер сюда не смотрит вовсе, поэтому ошибка здесь стоит не разговора, а
/// сходства с другими клиентами.
pub fn padding(payload_cipher: &[u8], length: usize) -> Vec<u8> {
    if length == 0 {
        return Vec::new();
    }

    let ones = count_ones(payload_cipher);
    let zeros = 8 * payload_cipher.len() - ones;
    if zeros == 0 {
        return random(length);
    }

    let ratio = ones as f64 / zeros as f64;
    if ratio <= 0.5 || ratio >= 1.6 {
        return random(length);
    }

    let base = if zeros < ones { 0.4 } else { 1.6 };
    let target = base + rand::thread_rng().gen_range(0.0..1.0) / 10.0;
    let total_bits = 8 * (length + payload_cipher.len());
    let want = (total_bits as f64 * (target / (target + 1.0))) - ones as f64;

    if want < 0.0 || want > (8 * length) as f64 {
        return random(length);
    }
    with_ones(length, want as usize)
}

/// Случайное дополнение.
pub fn random(length: usize) -> Vec<u8> {
    let mut out = vec![0u8; length];
    rand::thread_rng().fill(&mut out[..]);
    out
}

/// Сколько единичных бит в данных.
///
/// Считаются не все байты, а первые кратные четырём: так у эталона. Смысла в
/// этом не видно, но доля считается по этому числу, и считать иначе значит
/// подбирать дополнение под другую долю.
fn count_ones(bytes: &[u8]) -> usize {
    let limit = bytes.len() & !3;
    bytes[..limit]
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum()
}

/// Дополнение ровно с таким числом единичных бит, разложенных вперемешку.
fn with_ones(length: usize, ones: usize) -> Vec<u8> {
    let total = 8 * length;
    let ones = ones.min(total);

    let mut bits = vec![false; total];
    bits[..ones].fill(true);

    // Перемешивание Фишера — Йетса: без него единицы легли бы в начало, и
    // дополнение выглядело бы одинаково у каждого кадра.
    let mut rng = rand::thread_rng();
    for at in (1..total).rev() {
        bits.swap(at, rng.gen_range(0..=at));
    }

    let mut out = vec![0u8; length];
    for (at, set) in bits.into_iter().enumerate() {
        if set {
            out[at / 8] |= 1 << (at % 8);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_says_what_it_carries() {
        let plain = header(0x0102, 0x0304);
        assert_eq!(plain, [4, 0, 0, 0x01, 0x02, 0x03, 0x04]);

        let parsed = parse(&plain).expect("разбирается");
        assert_eq!(parsed.padding, 0x0102);
        assert_eq!(parsed.payload, 0x0304);
    }

    #[test]
    fn a_header_of_another_version_is_refused() {
        // Первый байт и есть версия кадра: чужой означает, что на том конце
        // не четвёртая версия, и продолжать нечего.
        let mut plain = header(0, 1);
        plain[0] = 3;
        assert!(parse(&plain).is_none());
        assert!(parse(&[4, 0, 0]).is_none(), "обрезанный заголовок");
    }

    #[test]
    fn a_length_beyond_the_limit_is_refused() {
        let mut plain = header(0, 1);
        plain[5..7].copy_from_slice(&0xFFFF_u16.to_be_bytes());
        assert!(parse(&plain).is_none());
    }

    #[test]
    fn the_swap_undoes_itself() {
        // На этом держится разбор: тот, кто читает, зовёт то же самое.
        let original_padding = vec![1u8, 2, 3, 4, 5, 6, 7];
        let original_payload = vec![10u8, 20, 30, 40];

        let mut padding = original_padding.clone();
        let mut payload = original_payload.clone();
        swap(&mut padding, &mut payload);
        assert_ne!(padding, original_padding, "ничего не поменялось");

        swap(&mut padding, &mut payload);
        assert_eq!(padding, original_padding);
        assert_eq!(payload, original_payload);
    }

    #[test]
    fn the_swap_touches_only_the_even_bytes_and_only_the_shorter_of_the_two() {
        let mut padding = vec![1u8, 2, 3, 4, 5];
        let mut payload = vec![10u8, 20];
        swap(&mut padding, &mut payload);

        assert_eq!(padding, [10, 2, 3, 4, 5], "нечётные или лишние тронуты");
        assert_eq!(payload, [1, 20]);
    }

    #[test]
    fn the_padding_is_as_long_as_asked() {
        let payload = vec![0xA5u8; 64];
        for length in [0, 1, 7, 256, 1000] {
            assert_eq!(padding(&payload, length).len(), length, "{length}");
        }
    }

    #[test]
    fn the_padding_of_all_ones_payload_falls_back_to_random() {
        // Нулевых бит нет — доли не посчитать, и эталон в этом случае берёт
        // случайные байты.
        let payload = vec![0xFFu8; 8];
        assert_eq!(padding(&payload, 16).len(), 16);
    }

    #[test]
    fn the_bit_count_padding_has_the_number_of_ones_it_was_asked_for() {
        for ones in [0, 1, 17, 64] {
            let out = with_ones(8, ones);
            let got: u32 = out.iter().map(|byte| byte.count_ones()).sum();
            assert_eq!(got as usize, ones);
        }
    }

    #[test]
    fn the_ones_are_not_all_at_the_beginning() {
        // Без перемешивания дополнение выглядело бы одинаково у каждого кадра.
        let out = with_ones(64, 256);
        assert_ne!(&out[..32], &[0xFFu8; 32], "единицы легли подряд");
    }

    #[test]
    fn the_count_of_ones_ignores_the_tail_the_way_the_reference_does() {
        // Считаются первые байты, кратные четырём. Считать иначе значит
        // подбирать дополнение под другую долю.
        assert_eq!(count_ones(&[0xFF, 0xFF, 0xFF]), 0, "хвост попал в счёт");
        assert_eq!(count_ones(&[0xFF, 0xFF, 0xFF, 0xFF]), 32);
        assert_eq!(count_ones(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), 32);
    }
}
