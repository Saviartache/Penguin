//! Кадр мультиплексора: семь байт заголовка и данные.
//!
//! ```text
//! +---------+-----------+--------+----------+
//! | команда |   поток   | длина  |  данные  |
//! +---------+-----------+--------+----------+
//! |    1    |  4 (BE)   | 2 (BE) |  0..16K  |
//! +---------+-----------+--------+----------+
//! ```
//!
//! Кадров в одной записи может быть сколько угодно — этим и пользуется
//! дополнение: [`PAD`] едет в той же записи, что и настоящие данные, и снаружи
//! их не разделить. Своего шифрования у кадра нет: запись уже зашифрована
//! целиком ([`crate::wire::record`]).
//!
//! # Номера потоков
//!
//! Потоки нумерует **только клиент**, и номер не переиспользуется. Сервер
//! своих потоков не открывает — открывать ему некуда: наружу он ходит по
//! просьбе клиента, а не наоборот. Поэтому гонки за номер здесь нет вовсе, и
//! чётности номеров, которая есть у HTTP/2, тоже нет.

use crate::error::{PingwinError, PingwinResult};
use crate::wire::record::MAX_PLAIN;

/// Дополнение: прочитать и выбросить. Номер потока не значит ничего.
pub const PAD: u8 = 0x00;
/// Открыть поток до адреса. Данные — адрес в записи SOCKS5.
pub const OPEN: u8 = 0x01;
/// Поток открыт.
pub const OPEN_OK: u8 = 0x02;
/// Поток открыть не удалось. Данные — причина текстом.
pub const OPEN_ERR: u8 = 0x03;
/// Данные потока.
pub const DATA: u8 = 0x04;
/// Данных с этой стороны больше не будет. Обратное направление живёт.
pub const FIN: u8 = 0x05;
/// Поток оборван. Данные — причина текстом.
pub const RST: u8 = 0x06;
/// Открыть датаграммный канал.
pub const UDP_BIND: u8 = 0x07;
/// Датаграмма. Данные — адрес в записи SOCKS5 и за ним тело.
pub const UDP: u8 = 0x08;
/// Проверка живости: на неё отвечают.
pub const PING: u8 = 0x09;
/// Ответ на проверку живости.
pub const PONG: u8 = 0x0A;

/// Длина заголовка кадра.
pub const HEADER_LEN: usize = 1 + 4 + 2;

/// Сколько данных помещается в кадр, чтобы он влез в запись целиком.
pub const MAX_PAYLOAD: usize = MAX_PLAIN - HEADER_LEN;

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

/// Дописывает кадр в буфер.
///
/// `Err` — данных больше, чем помещается в объявляемую длину. Резать их здесь
/// нельзя: длину пишем мы, а читает её собеседник, и разъедется вся сессия.
pub fn write(out: &mut Vec<u8>, cmd: u8, sid: u32, data: &[u8]) -> PingwinResult<()> {
    let len = u16::try_from(data.len()).map_err(|_| PingwinError::Oversized(data.len()))?;
    if data.len() > MAX_PAYLOAD {
        return Err(PingwinError::Oversized(data.len()));
    }
    out.extend_from_slice(&Header { cmd, sid, len }.encode());
    out.extend_from_slice(data);
    Ok(())
}

/// Собирает кадр отдельным буфером.
pub fn encode(cmd: u8, sid: u32, data: &[u8]) -> PingwinResult<Vec<u8>> {
    let mut out = Vec::with_capacity(HEADER_LEN + data.len());
    write(&mut out, cmd, sid, data)?;
    Ok(out)
}

/// Кадры внутри одной расшифрованной записи.
///
/// Обход прекращается на первом же кадре, который не помещается в запись:
/// продолжать после него нельзя — дальше идут не кадры, а хвост чужой длины.
pub struct Frames<'a> {
    rest: &'a [u8],
    broken: bool,
}

impl<'a> Frames<'a> {
    /// Начинает обход по расшифрованному телу записи.
    pub fn new(plain: &'a [u8]) -> Self {
        Self {
            rest: plain,
            broken: false,
        }
    }
}

impl<'a> Iterator for Frames<'a> {
    type Item = PingwinResult<(Header, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.broken || self.rest.is_empty() {
            return None;
        }
        let Some(head) = self.rest.first_chunk::<HEADER_LEN>() else {
            self.broken = true;
            return Some(Err(PingwinError::malformed(format!(
                "хвост записи — {} байт, а заголовок кадра семь",
                self.rest.len()
            ))));
        };
        let header = Header::decode(head);
        let len = usize::from(header.len);
        let body = &self.rest[HEADER_LEN..];
        if body.len() < len {
            self.broken = true;
            return Some(Err(PingwinError::malformed(format!(
                "кадр объявил {len} байт, а в записи их {}",
                body.len()
            ))));
        }
        self.rest = &body[len..];
        Some(Ok((header, &body[..len])))
    }
}

/// Имя команды для журнала.
pub fn name(cmd: u8) -> &'static str {
    match cmd {
        PAD => "PAD",
        OPEN => "OPEN",
        OPEN_OK => "OPEN_OK",
        OPEN_ERR => "OPEN_ERR",
        DATA => "DATA",
        FIN => "FIN",
        RST => "RST",
        UDP_BIND => "UDP_BIND",
        UDP => "UDP",
        PING => "PING",
        PONG => "PONG",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_is_seven_bytes_in_the_declared_order() {
        // Побайтно, а не круговым прогоном: свой разбор согласится сам с
        // собой при любой ошибке в порядке байт.
        let frame = encode(DATA, 0x0102_0304, b"ab").expect("собирается");
        assert_eq!(
            frame,
            [DATA, 0x01, 0x02, 0x03, 0x04, 0x00, 0x02, b'a', b'b']
        );
    }

    #[test]
    fn a_header_survives_the_round_trip() {
        let header = Header {
            cmd: OPEN,
            sid: 7,
            len: 0,
        };
        assert_eq!(Header::decode(&header.encode()), header);
    }

    #[test]
    fn several_frames_share_one_record() {
        // На этом стоит дополнение: `PAD` едет в той же записи, что и данные.
        let mut record = Vec::new();
        write(&mut record, DATA, 1, b"one").expect("собирается");
        write(&mut record, PAD, 0, &[0u8; 4]).expect("собирается");
        write(&mut record, DATA, 2, b"two").expect("собирается");

        let frames: Vec<_> = Frames::new(&record)
            .map(|frame| frame.expect("разбирается"))
            .collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].0.cmd, DATA);
        assert_eq!(frames[0].1, b"one");
        assert_eq!(frames[1].0.cmd, PAD);
        assert_eq!(frames[2].1, b"two");
    }

    #[test]
    fn a_truncated_frame_stops_the_walk_instead_of_reading_past_it() {
        // Продолжать после обрезанного кадра нельзя: дальше идут не кадры, а
        // хвост чужой длины, и «разобрать» его значит выдумать данные.
        let mut record = encode(DATA, 1, b"hello").expect("собирается");
        record.truncate(HEADER_LEN + 2);

        let mut frames = Frames::new(&record);
        assert!(frames.next().expect("кадр есть").is_err());
        assert!(frames.next().is_none(), "после ошибки обход продолжился");
    }

    #[test]
    fn a_tail_shorter_than_a_header_is_an_error_not_silence() {
        let mut frames = Frames::new(&[1, 2, 3]);
        assert!(frames.next().expect("кадр есть").is_err());
    }

    #[test]
    fn an_empty_record_has_no_frames() {
        assert!(Frames::new(&[]).next().is_none());
    }

    #[test]
    fn the_biggest_frame_fits_inside_one_record() {
        // Кадр, не влезающий в запись, пришлось бы резать — а резать его
        // некому: длину объявляет отправитель.
        let mut out = Vec::new();
        write(&mut out, DATA, 1, &vec![0; MAX_PAYLOAD]).expect("влезает");
        assert_eq!(out.len(), MAX_PLAIN);
        assert!(write(&mut Vec::new(), DATA, 1, &vec![0; MAX_PAYLOAD + 1]).is_err());
    }

    #[test]
    fn the_commands_do_not_share_numbers() {
        // Сдвиг на единицу превратил бы `FIN` в `RST`, и заметить это можно
        // было бы только по оборванной странице.
        let all = [
            PAD, OPEN, OPEN_OK, OPEN_ERR, DATA, FIN, RST, UDP_BIND, UDP, PING, PONG,
        ];
        assert_eq!(all, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        for cmd in all {
            assert_ne!(name(cmd), "?");
        }
    }
}
