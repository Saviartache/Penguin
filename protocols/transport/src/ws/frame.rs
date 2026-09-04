//! Кадр WebSocket: разбор и сборка (RFC 6455, §5).
//!
//! ```text
//!  0               1               2               3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-------+-+-------------+-------------------------------+
//! |F|R|R|R| код   |M| длина (7)   |  длина 16 или 64 бита, если    |
//! |I|S|S|S| (4)   |A|             |  в семи битах не поместилась   |
//! |N|V|V|V|       |S|             |                               |
//! | |1|2|3|       |K|             |                               |
//! +-+-+-+-+-------+-+-------------+- - - - - - - - - - - - - - - -+
//! |     ключ маски, если MASK     |          данные...            |
//! +-------------------------------+-------------------------------+
//! ```
//!
//! Чистые функции над срезами: ни сокетов, ни ожидания. Отсюда и тесты —
//! на записанных байтах, без сети.
//!
//! # Две вещи, на которых здесь ошибаются
//!
//! **Клиент обязан маскировать, сервер обязан не маскировать.** Немаскированный
//! кадр от клиента сервер закрывает с кодом 1002 — и выглядит это как «прокси
//! молча рвёт соединение». Маскировка не защищает ничего: ключ идёт рядом,
//! открытым текстом. Она нужна против промежуточных узлов, которые могли бы
//! принять содержимое кадра за начало нового запроса HTTP.
//!
//! **Длина объявляется той стороной, которой мы не управляем.** Восемь байт
//! длины позволяют объявить кадр в терабайт, и доверчивый разбор попробует
//! выделить под него память. Отсюда [`MAX_PAYLOAD`].

use crate::error::{TransportError, TransportResult};

/// Продолжение предыдущего кадра.
pub const OP_CONTINUATION: u8 = 0x0;
/// Текст. Мы такие не шлём, но получить можем.
pub const OP_TEXT: u8 = 0x1;
/// Двоичные данные. Всё, что уходит через прокси, — это они.
pub const OP_BINARY: u8 = 0x2;
/// Закрытие.
pub const OP_CLOSE: u8 = 0x8;
/// Проверка связи.
pub const OP_PING: u8 = 0x9;
/// Ответ на проверку связи.
pub const OP_PONG: u8 = 0xA;

/// Наибольший кадр, который мы согласны принять.
///
/// Восемь байт длины позволяют объявить кадр в терабайт. Верить объявленному
/// значит отдать памяти столько, сколько скажет тот конец, — а он не наш.
/// Восемь мегабайт заведомо больше всего, что шлёт любой разумный сервер, и
/// заведомо меньше того, чем можно уронить машину.
pub const MAX_PAYLOAD: usize = 8 * 1024 * 1024;

/// Наибольший кадр, который шлём мы.
///
/// Резать поток на куски приходится всё равно: приложение может отдать разом
/// мегабайт, а держать его целиком в буфере незачем.
pub const MAX_SEND: usize = 64 * 1024;

/// Разобранный заголовок кадра.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Последний кадр сообщения.
    pub fin: bool,
    /// Код операции.
    pub opcode: u8,
    /// Данные замаскированы.
    pub masked: bool,
    /// Длина данных.
    pub len: usize,
    /// Ключ маски. Значим только при `masked`.
    pub mask: [u8; 4],
    /// Сколько байт занял сам заголовок.
    pub header_len: usize,
}

impl Header {
    /// Общая длина кадра: заголовок и данные.
    pub fn total_len(&self) -> usize {
        self.header_len + self.len
    }

    /// Это управляющий кадр: закрытие, проверка связи, ответ на неё.
    pub fn is_control(&self) -> bool {
        self.opcode & 0x08 != 0
    }
}

/// Читает заголовок с начала среза.
///
/// `Ok(None)` — байт пока не хватает. Это не ошибка: кадр приходит по частям,
/// и отличать «неполно» от «сломано» обязан тот, кто читает.
pub fn decode_header(bytes: &[u8]) -> TransportResult<Option<Header>> {
    let Some(first) = bytes.first_chunk::<2>() else {
        return Ok(None);
    };
    let fin = first[0] & 0x80 != 0;
    let opcode = first[0] & 0x0F;
    let masked = first[1] & 0x80 != 0;
    let short = usize::from(first[1] & 0x7F);

    // Управляющий кадр не бывает ни длиннее 125 байт, ни разрезанным
    // (RFC 6455, §5.5). Нарушение означает, что на том конце не WebSocket.
    if opcode & 0x08 != 0 && (short > 125 || !fin) {
        return Err(TransportError::malformed(
            "управляющий кадр длиннее 125 байт или разрезан",
        ));
    }

    let (len, len_bytes) = match short {
        126 => match bytes.get(2..4).and_then(<[u8]>::first_chunk::<2>) {
            Some(raw) => (usize::from(u16::from_be_bytes(*raw)), 2),
            None => return Ok(None),
        },
        127 => match bytes.get(2..10).and_then(<[u8]>::first_chunk::<8>) {
            Some(raw) => {
                let len = u64::from_be_bytes(*raw);
                // На 32-битной машине `as usize` обрезал бы длину молча.
                let len = usize::try_from(len)
                    .map_err(|_| TransportError::malformed("кадр длиннее памяти машины"))?;
                (len, 8)
            }
            None => return Ok(None),
        },
        other => (other, 0),
    };

    if len > MAX_PAYLOAD {
        return Err(TransportError::malformed(format!(
            "кадр в {len} байт: больше, чем мы готовы принять"
        )));
    }

    let header_len = 2 + len_bytes + if masked { 4 } else { 0 };
    let mut mask = [0u8; 4];
    if masked {
        let Some(raw) = bytes
            .get(2 + len_bytes..header_len)
            .and_then(<[u8]>::first_chunk::<4>)
        else {
            return Ok(None);
        };
        mask = *raw;
    }

    Ok(Some(Header {
        fin,
        opcode,
        masked,
        len,
        mask,
        header_len,
    }))
}

/// Собирает кадр целиком: заголовок, ключ маски, замаскированные данные.
///
/// Маска обязательна: клиент, приславший немаскированный кадр, для сервера —
/// нарушитель протокола, и закрывает он такое соединение молча.
pub fn encode(opcode: u8, fin: bool, payload: &[u8], mask: [u8; 4], out: &mut Vec<u8>) {
    out.push(if fin { 0x80 | opcode } else { opcode });

    let len = payload.len();
    if len < 126 {
        out.push(0x80 | len as u8);
    } else if len <= usize::from(u16::MAX) {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }

    out.extend_from_slice(&mask);
    let start = out.len();
    out.extend_from_slice(payload);
    apply_mask(&mut out[start..], mask, 0);
}

/// Накладывает маску. Обратная операция — она же: это XOR.
///
/// `offset` — сколько байт данных уже прошло через маску раньше. Нужен
/// потому, что кадр приходит по частям, а ключ идёт по кругу от начала
/// **данных**, а не от начала куска.
pub fn apply_mask(data: &mut [u8], mask: [u8; 4], offset: usize) {
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= mask[(offset + index) % 4];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASK: [u8; 4] = [0x37, 0xFA, 0x21, 0x3D];

    #[test]
    fn a_short_frame_matches_the_rfc_example() {
        // Пример из RFC 6455, §5.7: замаскированное «Hello» текстовым кадром.
        let mut out = Vec::new();
        encode(OP_TEXT, true, b"Hello", MASK, &mut out);
        assert_eq!(
            out,
            [
                0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58
            ]
        );
    }

    #[test]
    fn masking_is_its_own_inverse() {
        let mut data = "данные приложения".as_bytes().to_vec();
        let original = data.clone();
        apply_mask(&mut data, MASK, 0);
        assert_ne!(data, original, "маска ничего не изменила");
        apply_mask(&mut data, MASK, 0);
        assert_eq!(data, original);
    }

    #[test]
    fn the_mask_runs_from_the_start_of_the_data() {
        // Кадр приходит по частям, и ключ идёт по кругу от начала данных, а
        // не от начала куска. Ошибка здесь портит каждый четвёртый байт.
        let mut whole = (0u8..40).collect::<Vec<_>>();
        let mut split = whole.clone();
        apply_mask(&mut whole, MASK, 0);

        let (head, tail) = split.split_at_mut(7);
        apply_mask(head, MASK, 0);
        apply_mask(tail, MASK, 7);
        assert_eq!(whole, split);
    }

    #[test]
    fn every_length_form_round_trips() {
        for len in [0usize, 1, 125, 126, 127, 1000, 65535, 65536, 70000] {
            let payload = vec![0xA5; len];
            let mut out = Vec::new();
            encode(OP_BINARY, true, &payload, MASK, &mut out);

            let header = decode_header(&out).expect("не сломано").expect("целиком");
            assert_eq!(header.len, len, "длина {len}");
            assert!(header.fin && header.masked);
            assert_eq!(header.opcode, OP_BINARY);
            assert_eq!(header.total_len(), out.len());

            let mut data = out[header.header_len..].to_vec();
            apply_mask(&mut data, header.mask, 0);
            assert_eq!(data, payload, "длина {len}");
        }
    }

    #[test]
    fn a_half_read_header_is_not_an_error() {
        let mut out = Vec::new();
        encode(OP_BINARY, true, &vec![0u8; 70000], MASK, &mut out);

        for cut in 0..14 {
            assert!(
                decode_header(&out[..cut]).expect("не сломано").is_none(),
                "обрезанный до {cut} байт заголовок разобрался"
            );
        }
    }

    #[test]
    fn an_absurd_length_is_refused_before_the_allocation() {
        // 0x7F и восемь байт длины: сервер объявляет кадр в терабайт.
        let announced = [0x82, 0xFF, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0];
        assert!(decode_header(&announced).is_err());
    }

    #[test]
    fn a_control_frame_may_be_neither_long_nor_split() {
        // Разрезанный `ping` означает, что на том конце не WebSocket.
        assert!(decode_header(&[0x09, 0x7E, 0x01, 0x00]).is_err());
        assert!(decode_header(&[0x09, 0x00]).is_err(), "FIN не выставлен");
        decode_header(&[0x89, 0x00])
            .expect("не сломано")
            .expect("целиком");
    }

    #[test]
    fn a_server_frame_carries_no_mask() {
        // Сервер маскировать не обязан и не должен; заголовок от него на два
        // байта короче.
        let header = decode_header(&[0x82, 0x05, 1, 2, 3, 4, 5])
            .expect("не сломано")
            .expect("целиком");
        assert!(!header.masked);
        assert_eq!(header.header_len, 2);
        assert_eq!(header.len, 5);
    }

    #[test]
    fn control_frames_are_told_apart() {
        for opcode in [OP_CLOSE, OP_PING, OP_PONG] {
            let header = decode_header(&[0x80 | opcode, 0x00])
                .expect("не сломано")
                .expect("целиком");
            assert!(header.is_control(), "{opcode:#x}");
        }
        for opcode in [OP_CONTINUATION, OP_TEXT, OP_BINARY] {
            let header = decode_header(&[0x80 | opcode, 0x00])
                .expect("не сломано")
                .expect("целиком");
            assert!(!header.is_control(), "{opcode:#x}");
        }
    }
}
