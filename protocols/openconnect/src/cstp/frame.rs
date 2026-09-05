//! Кадр CSTP: как IP-пакет заворачивается в поток TLS.
//!
//! Формат сверен байт в байт с `openconnect/cstp.c` (структура заголовка,
//! функция `cstp_write`) и с `ocserv/src/worker-vpn.c` (`parse_cstp_data`) —
//! обе стороны требуют его один в один:
//!
//! ```text
//!  байт 0..4   магия "STF\x01"
//!  байт 4..6   длина полезной нагрузки, big-endian, БЕЗ учёта этих 8 байт
//!  байт 6      тип пакета
//!  байт 7      не используется, всегда 0
//!  байт 8..    полезная нагрузка (IP-пакет либо пусто у служебных кадров)
//! ```
//!
//! Это формат только для TCP-канала. У DTLS (которого здесь нет — см. документ
//! крейта) кадр устроен иначе: один байт типа перед данными, без магии и без
//! длины, — длину там несёт сама запись DTLS. Смешивать эти два формата
//! нельзя: типовые константы совпадают, а заголовок — нет.

use crate::error::{OpenConnectError, OpenConnectResult};

/// Магия в начале каждого кадра TCP-CSTP.
const MAGIC: [u8; 4] = *b"STF\x01";

/// Размер заголовка: магия (4) + длина (2) + тип (1) + резерв (1).
pub const HEADER_LEN: usize = 8;

/// Тип кадра: обычные данные — IP-пакет как есть.
pub const DATA: u8 = 0;
/// Тип кадра: проверка живости, запрос («ты жив?»).
pub const DPD_OUT: u8 = 3;
/// Тип кадра: проверка живости, ответ.
pub const DPD_RESP: u8 = 4;
/// Тип кадра: клиент прощается сам. Первый байт нагрузки — `0xb0`
/// (`cstp.c: cstp_bye`), остальное — текст причины для журнала сервера.
pub const DISCONN: u8 = 5;
/// Тип кадра: обычное поддержание соединения, без ответа.
pub const KEEPALIVE: u8 = 7;
/// Тип кадра: сервор разрывает соединение сам (`AC_PKT_TERM_SERVER`).
pub const TERM_SERVER: u8 = 9;

/// Первый байт нагрузки кадра [`DISCONN`], которым клиент помечает
/// добровольный выход (`cstp.c: cstp_bye`, `0xb0`). Любой другой первый байт
/// (или пустая нагрузка) сервер читает как временный обрыв, после которого
/// клиент собирается переподключиться (`worker-vpn.c`), — то есть эту метку
/// нельзя просто опустить, не соврав серверу о причине.
pub const DISCONN_USER_QUIT: u8 = 0xb0;

/// Собирает кадр целиком: заголовок и нагрузку одним куском.
///
/// Отдельная функция, а не запись прямо в сокет, — чтобы кадр можно было
/// проверить на срезе байт, без TLS и без сети.
pub fn encode(kind: u8, payload: &[u8]) -> OpenConnectResult<Vec<u8>> {
    let len: u16 = payload.len().try_into().map_err(|_| {
        OpenConnectError::frame(format!("пакет в {} байт длиннее 65535", payload.len()))
    })?;

    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&MAGIC);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.push(kind);
    frame.push(0); // резерв, всегда 0
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Кадр без нагрузки — то, чем клиент сам поддерживает связь и проверяет
/// живость (`mainloop.c: keepalive_action` шлёт оба нулевой длины).
///
/// Отдельно от [`encode`]: длина здесь всегда влезает в `u16`, и заводить
/// ради этого `Result` незачем — там, где кадр собирает сам клиент, а не
/// пересылает чужую нагрузку, ошибке взяться неоткуда.
pub fn encode_empty(kind: u8) -> [u8; HEADER_LEN] {
    let mut frame = [0u8; HEADER_LEN];
    frame[..4].copy_from_slice(&MAGIC);
    frame[6] = kind;
    frame
}

/// Разобранный заголовок: тип кадра и длина нагрузки, которая идёт следом.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Тип кадра: [`DATA`], [`KEEPALIVE`] и так далее.
    pub kind: u8,
    /// Длина нагрузки в байтах — сколько читать после заголовка.
    pub len: usize,
}

/// Разбирает заголовок из первых [`HEADER_LEN`] байт.
///
/// Нагрузку не трогает: её читают отдельно, когда придёт целиком, — TLS
/// отдаёт байты кусками произвольного размера, и требовать кадр одним чтением
/// значило бы падать на первом же сервере, приславшем его в двух пакетах.
pub fn decode_header(bytes: &[u8]) -> OpenConnectResult<Header> {
    if bytes.len() < HEADER_LEN {
        return Err(OpenConnectError::frame(format!(
            "заголовок кадра короче {HEADER_LEN} байт"
        )));
    }
    if bytes[..4] != MAGIC {
        return Err(OpenConnectError::frame(
            "нет магии `STF\\x01`: на том конце не CSTP",
        ));
    }
    let len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    Ok(Header {
        kind: bytes[6],
        len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_data_frame_round_trips() {
        let payload = b"IP packet here";
        let frame = encode(DATA, payload).expect("собирается");
        assert_eq!(&frame[..4], b"STF\x01");

        let header = decode_header(&frame).expect("разбирается");
        assert_eq!(header.kind, DATA);
        assert_eq!(header.len, payload.len());
        assert_eq!(&frame[HEADER_LEN..], payload);
    }

    #[test]
    fn the_length_excludes_the_header_itself() {
        // Сервер (`worker-vpn.c`) читает длину как размер одной только
        // нагрузки; включить восемь байт заголовка значило бы читать восемь
        // лишних байт из следующего кадра.
        let frame = encode(KEEPALIVE, &[]).expect("собирается");
        assert_eq!(frame.len(), HEADER_LEN);
        assert_eq!(decode_header(&frame).expect("разбирается").len, 0);
    }

    #[test]
    fn the_reserved_byte_is_always_zero() {
        let frame = encode(DATA, b"x").expect("собирается");
        assert_eq!(frame[7], 0);
    }

    #[test]
    fn missing_magic_is_told_apart_from_a_short_read() {
        let mut frame = encode(DATA, b"x").expect("собирается");
        frame[0] = b'X';
        let err = decode_header(&frame).expect_err("не CSTP");
        assert!(err.to_string().contains("магии"), "{err}");
    }

    #[test]
    fn a_header_shorter_than_eight_bytes_is_not_enough_yet() {
        // Не ошибка формата: TLS вправе прислать заголовок по частям, и это
        // означает «подожди ещё байт», а не «на том конце не CSTP».
        let err = decode_header(&[0u8; 4]).expect_err("рано");
        assert!(err.to_string().contains("короче"), "{err}");
    }

    #[test]
    fn an_oversized_packet_is_refused_before_it_is_sent() {
        let huge = vec![0u8; usize::from(u16::MAX) + 1];
        assert!(encode(DATA, &huge).is_err());
    }

    #[test]
    fn an_empty_frame_still_carries_the_magic_and_the_type() {
        let frame = encode_empty(KEEPALIVE);
        assert_eq!(frame.len(), HEADER_LEN);
        let header = decode_header(&frame).expect("разбирается");
        assert_eq!(header.kind, KEEPALIVE);
        assert_eq!(header.len, 0);
    }

    #[test]
    fn a_quit_notice_carries_its_marker_byte() {
        // Без него сервер учтёт выход как временный обрыв, а не как
        // добровольное отключение (`worker-vpn.c`).
        let mut payload = vec![DISCONN_USER_QUIT];
        payload.extend_from_slice("пользователь отключился".as_bytes());
        let frame = encode(DISCONN, &payload).expect("собирается");
        assert_eq!(frame[HEADER_LEN], DISCONN_USER_QUIT);
    }
}
