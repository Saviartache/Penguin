//! Кадр сессии: семь байт заголовка и данные.
//!
//! ```text
//! +---------+-----------+--------+----------+
//! | команда |   поток   | длина  |  данные  |
//! +---------+-----------+--------+----------+
//! |    1    |  4 (BE)   | 2 (BE) |  0..64K  |
//! +---------+-----------+--------+----------+
//! ```
//!
//! Кадры едут внутри одного соединения TLS вперемешку: номер потока говорит,
//! кому принадлежат данные. Своего шифрования у кадра нет — всё шифрует TLS.
//!
//! Данных не носит ни одна команда, кроме перечисленных в их описаниях. Кадр
//! с неожиданными данными не роняет сессию: длина всё равно объявлена, и
//! данные читаются и выбрасываются (см. [`crate::reader`]).

use crate::error::{AnyTlsError, AnyTlsResult};

/// Дополнение: прочитать и молча выбросить. Носит данные.
pub const CMD_WASTE: u8 = 0;
/// Открыть поток.
pub const CMD_SYN: u8 = 1;
/// Данные потока. Носит данные.
pub const CMD_PSH: u8 = 2;
/// Закрыть поток. Закрывает его целиком, в обе стороны.
pub const CMD_FIN: u8 = 3;
/// Настройки клиента. Носит данные.
pub const CMD_SETTINGS: u8 = 4;
/// Отказ сервера. Носит данные: текст причины.
pub const CMD_ALERT: u8 = 5;
/// Новая схема дополнения от сервера. Носит данные.
pub const CMD_UPDATE_PADDING: u8 = 6;
/// Сервер открыл поток. Носит данные, только если это ошибка.
pub const CMD_SYN_ACK: u8 = 7;
/// Проверка живости: на неё отвечают.
pub const CMD_HEART_REQUEST: u8 = 8;
/// Ответ на проверку живости.
pub const CMD_HEART_RESPONSE: u8 = 9;
/// Настройки сервера. Носит данные.
pub const CMD_SERVER_SETTINGS: u8 = 10;

/// Длина заголовка.
pub const HEADER_LEN: usize = 1 + 4 + 2;

/// Сколько данных помещается в один кадр.
pub const MAX_PAYLOAD: usize = u16::MAX as usize;

/// Разобранный заголовок.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Команда.
    pub cmd: u8,
    /// Номер потока. У кадров, не принадлежащих потоку, — ноль.
    pub sid: u32,
    /// Длина данных за заголовком.
    pub len: u16,
}

impl Header {
    /// Разбирает заголовок.
    pub fn decode(bytes: &[u8; HEADER_LEN]) -> Self {
        Self {
            cmd: bytes[0],
            sid: u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]),
            len: u16::from_be_bytes([bytes[5], bytes[6]]),
        }
    }

    /// Записывает заголовок.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let sid = self.sid.to_be_bytes();
        let len = self.len.to_be_bytes();
        [self.cmd, sid[0], sid[1], sid[2], sid[3], len[0], len[1]]
    }
}

/// Собирает кадр целиком: заголовок и данные за ним.
///
/// `Err` — данных больше, чем помещается в объявляемую длину. Резать их здесь
/// нельзя: длину пишем мы, а читает её сервер, и разъедется вся сессия.
pub fn encode(cmd: u8, sid: u32, data: &[u8]) -> AnyTlsResult<Vec<u8>> {
    let len = u16::try_from(data.len()).map_err(|_| AnyTlsError::Oversized(data.len()))?;
    let header = Header { cmd, sid, len }.encode();

    let mut frame = Vec::with_capacity(HEADER_LEN + data.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(data);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_is_seven_bytes_in_the_order_the_reference_names() {
        // Побайтно, а не круговым прогоном: свой разбор согласится сам с
        // собой при любой ошибке в порядке байт.
        let frame = encode(CMD_PSH, 0x0102_0304, b"ab").expect("собирается");
        assert_eq!(
            frame,
            [0x02, 0x01, 0x02, 0x03, 0x04, 0x00, 0x02, b'a', b'b']
        );
    }

    #[test]
    fn a_header_survives_the_round_trip() {
        let header = Header {
            cmd: CMD_SYN,
            sid: 7,
            len: 0,
        };
        assert_eq!(Header::decode(&header.encode()), header);
    }

    #[test]
    fn a_frame_without_data_is_just_the_header() {
        let frame = encode(CMD_FIN, 9, &[]).expect("собирается");
        assert_eq!(frame.len(), HEADER_LEN);
        assert_eq!(
            Header::decode(frame.first_chunk().expect("семь байт")).len,
            0
        );
    }

    #[test]
    fn the_biggest_frame_fits_and_the_next_one_does_not() {
        // Длина пишется двумя байтами: то, что длиннее, молча уехало бы не
        // той длиной, и разъехалась бы вся сессия.
        assert!(encode(CMD_PSH, 1, &vec![0; MAX_PAYLOAD]).is_ok());
        assert!(encode(CMD_PSH, 1, &vec![0; MAX_PAYLOAD + 1]).is_err());
    }

    #[test]
    fn the_commands_are_numbered_the_way_the_reference_numbers_them() {
        // Сдвиг на единицу превратил бы данные в дополнение, и заметить это
        // можно было бы только по молчанию сервера.
        assert_eq!(
            [
                CMD_WASTE,
                CMD_SYN,
                CMD_PSH,
                CMD_FIN,
                CMD_SETTINGS,
                CMD_ALERT,
                CMD_UPDATE_PADDING,
                CMD_SYN_ACK,
                CMD_HEART_REQUEST,
                CMD_HEART_RESPONSE,
                CMD_SERVER_SETTINGS,
            ],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        );
    }
}
