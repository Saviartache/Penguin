//! Команды протокола: заголовок в два байта и то, что за ним.
//!
//! ```text
//! +-----+------+----------+
//! | VER | TYPE |  OPT...  |
//! +-----+------+----------+
//! |  1  |  1   | сколько  |
//! +-----+------+----------+
//! ```
//!
//! | Команда | Код | Чем едет | Что несёт |
//! |---|---|---|---|
//! | `Authenticate` | `0x00` | односторонний поток | UUID и 32 байта отпечатка |
//! | `Connect` | `0x01` | двусторонний поток | адрес назначения |
//! | `Packet` | `0x02` | односторонний поток **или** датаграмма | кусок датаграммы |
//! | `Dissociate` | `0x03` | односторонний поток | конец UDP-сессии |
//! | `Heartbeat` | `0x04` | датаграмма | ничего |
//!
//! # Отпечаток проверки подлинности
//!
//! Он не выводится из пароля напрямую. Тридцать два байта берутся **экспортом
//! ключевого материала того самого соединения TLS**, где меткой служит UUID, а
//! исходными данными — пароль.
//!
//! Смысл в том, что отпечаток привязан к конкретному рукопожатию: подслушанный
//! в одном соединении, в другом он не подойдёт. Отсюда же и то, что посчитать
//! его заранее нельзя — только после того, как QUIC установлен.
//!
//! **Метка — шестнадцать сырых байт UUID, а не его запись с дефисами.** В
//! эталоне это `string(uuid[:])`, то есть побайтовое преобразование, а не
//! `uuid.String()`. Ошибиться здесь легко, а выглядит ошибка как молчащий
//! сервер: отпечаток не сойдётся, и сервер закроет соединение без объяснений.
//!
//! # Ответа нет ни на что
//!
//! Ни `Authenticate`, ни `Connect` сервер не подтверждает: после `Connect`
//! данные идут сразу, не дожидаясь ответа. Значит, неверный пароль виден
//! только тем, что соединение закрылось, — и различить его можно лишь по коду
//! закрытия QUIC.

use penguin_core::address::SocketAddress;
use penguin_core::uuid::Uuid;

use crate::error::TuicResult;
use crate::frame::address;

/// Версия протокола.
pub const VERSION: u8 = 0x05;

/// Проверка подлинности.
pub const CMD_AUTHENTICATE: u8 = 0x00;
/// Открыть поток до адреса назначения.
pub const CMD_CONNECT: u8 = 0x01;
/// Кусок датаграммы.
pub const CMD_PACKET: u8 = 0x02;
/// Конец UDP-сессии.
pub const CMD_DISSOCIATE: u8 = 0x03;
/// Поддержание соединения.
pub const CMD_HEARTBEAT: u8 = 0x04;

/// Длина отпечатка проверки подлинности.
pub const TOKEN_LEN: usize = 32;

/// Сколько байт занимает команда проверки подлинности целиком.
pub const AUTHENTICATE_LEN: usize = 2 + 16 + TOKEN_LEN;

/// Заголовок команды: версия и тип.
fn head(command: u8, out: &mut Vec<u8>) {
    out.push(VERSION);
    out.push(command);
}

/// Собирает команду проверки подлинности.
pub fn authenticate(uuid: &Uuid, token: &[u8; TOKEN_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AUTHENTICATE_LEN);
    head(CMD_AUTHENTICATE, &mut out);
    out.extend_from_slice(uuid.as_bytes());
    out.extend_from_slice(token);
    out
}

/// Собирает команду открытия потока.
pub fn connect(target: &SocketAddress) -> TuicResult<Vec<u8>> {
    let mut out = Vec::with_capacity(2 + address::encoded_len(Some(target)));
    head(CMD_CONNECT, &mut out);
    address::encode(Some(target), &mut out)?;
    Ok(out)
}

/// Заголовок куска датаграммы.
///
/// Поля идут ровно в этом порядке: номер сессии, номер датаграммы, сколько
/// всего кусков, какой это кусок, длина куска, адрес.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Номер UDP-сессии. Свой на каждый канал датаграмм.
    pub association: u16,
    /// Номер датаграммы внутри сессии. По нему собираются куски.
    pub packet: u16,
    /// Сколько всего кусков у этой датаграммы.
    pub fragments: u8,
    /// Какой это кусок, считая с нуля.
    pub fragment: u16,
    /// Длина данных этого куска.
    pub size: u16,
    /// Адрес. У всех кусков, кроме первого, его нет.
    pub address: Option<SocketAddress>,
}

impl Packet {
    /// Собирает заголовок куска.
    ///
    /// `Err` — номер куска не помещается в байт: кусков у датаграммы не
    /// бывает больше 255, и молча обрезать номер значит собрать её неверно.
    pub fn encode(&self) -> TuicResult<Vec<u8>> {
        let fragment = u8::try_from(self.fragment).map_err(|_| {
            crate::error::TuicError::malformed(format!("кусок номер {}", self.fragment))
        })?;

        let mut out = Vec::with_capacity(2 + 8 + address::encoded_len(self.address.as_ref()));
        head(CMD_PACKET, &mut out);
        out.extend_from_slice(&self.association.to_be_bytes());
        out.extend_from_slice(&self.packet.to_be_bytes());
        out.push(self.fragments);
        out.push(fragment);
        out.extend_from_slice(&self.size.to_be_bytes());
        address::encode(self.address.as_ref(), &mut out)?;
        Ok(out)
    }

    /// Читает заголовок куска с начала среза, **без** заголовка команды.
    ///
    /// Возвращает заголовок и число съеденных байт. `Ok(None)` — байт пока не
    /// хватает.
    pub fn decode(bytes: &[u8]) -> TuicResult<Option<(Self, usize)>> {
        let Some(fixed) = bytes.first_chunk::<8>() else {
            return Ok(None);
        };

        let association = u16::from_be_bytes([fixed[0], fixed[1]]);
        let packet = u16::from_be_bytes([fixed[2], fixed[3]]);
        let fragments = fixed[4];
        let fragment = u16::from(fixed[5]);
        let size = u16::from_be_bytes([fixed[6], fixed[7]]);

        let Some((address, used)) = address::decode(&bytes[8..])? else {
            return Ok(None);
        };

        Ok(Some((
            Self {
                association,
                packet,
                fragments,
                fragment,
                size,
                address,
            },
            8 + used,
        )))
    }
}

/// Собирает команду конца UDP-сессии.
pub fn dissociate(association: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    head(CMD_DISSOCIATE, &mut out);
    out.extend_from_slice(&association.to_be_bytes());
    out
}

/// Собирает команду поддержания соединения.
pub fn heartbeat() -> Vec<u8> {
    let mut out = Vec::with_capacity(2);
    head(CMD_HEARTBEAT, &mut out);
    out
}

/// Читает заголовок команды: версию и тип.
///
/// `Ok(None)` — байт пока не хватает.
pub fn read_head(bytes: &[u8]) -> TuicResult<Option<(u8, usize)>> {
    let Some(head) = bytes.first_chunk::<2>() else {
        return Ok(None);
    };
    if head[0] != VERSION {
        return Err(crate::error::TuicError::malformed(format!(
            "версия {:#04x} вместо {VERSION:#04x}",
            head[0]
        )));
    }
    Ok(Some((head[1], 2)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn uuid() -> Uuid {
        TEXT.parse().expect("разбирается")
    }

    #[test]
    fn every_command_starts_with_the_version() {
        // Версия — первое, что читает сервер: не та означает, что на порту не
        // TUIC, и дальше разбирать нечего.
        let commands = [
            authenticate(&uuid(), &[0u8; TOKEN_LEN]),
            connect(&SocketAddress::domain("a.io", 443)).expect("собирается"),
            dissociate(7),
            heartbeat(),
        ];
        for command in commands {
            assert_eq!(command[0], VERSION, "версия не на месте");
        }
    }

    #[test]
    fn the_authenticate_command_is_the_length_the_spec_names() {
        // 2 + 16 + 32: заголовок, UUID, отпечаток. Иначе сервер прочитает
        // отпечаток не оттуда.
        let command = authenticate(&uuid(), &[0xAB; TOKEN_LEN]);
        assert_eq!(command.len(), AUTHENTICATE_LEN);
        assert_eq!(command[1], CMD_AUTHENTICATE);
        assert_eq!(&command[2..18], uuid().as_bytes());
        assert_eq!(&command[18..], &[0xAB; TOKEN_LEN]);
    }

    #[test]
    fn the_connect_command_carries_the_address() {
        let command = connect(&SocketAddress::domain("a.io", 443)).expect("собирается");
        assert_eq!(command[1], CMD_CONNECT);
        assert_eq!(
            &command[2..],
            &[0x00, 4, b'a', b'.', b'i', b'o', 0x01, 0xBB]
        );
    }

    #[test]
    fn a_packet_header_round_trips() {
        let header = Packet {
            association: 0x0102,
            packet: 0x0304,
            fragments: 3,
            fragment: 1,
            size: 1200,
            address: Some(SocketAddress::domain("dns.example.com", 53)),
        };

        let wire = header.encode().expect("собирается");
        assert_eq!(wire[1], CMD_PACKET);

        let (back, used) = Packet::decode(&wire[2..])
            .expect("разбирается")
            .expect("целиком");
        assert_eq!(back, header);
        assert_eq!(used, wire.len() - 2);
    }

    #[test]
    fn the_fixed_fields_are_where_the_spec_says() {
        // Порядок полей: сессия, датаграмма, всего кусков, номер куска, длина,
        // адрес. Перепутанные местами номера собирают датаграмму из чужих
        // кусков — и это не видно ни на сборке, ни на первом пакете.
        let header = Packet {
            association: 0x0102,
            packet: 0x0304,
            fragments: 3,
            fragment: 1,
            size: 0x04B0,
            address: None,
        };
        let wire = header.encode().expect("собирается");
        assert_eq!(
            wire,
            [
                VERSION, CMD_PACKET, 0x01, 0x02, 0x03, 0x04, 3, 1, 0x04, 0xB0, 0xff
            ]
        );
    }

    #[test]
    fn only_the_first_fragment_carries_the_address() {
        // Адрес назван один раз; в остальных кусках стоит «адреса нет».
        let tail = Packet {
            association: 1,
            packet: 1,
            fragments: 3,
            fragment: 2,
            size: 100,
            address: None,
        };
        let wire = tail.encode().expect("собирается");
        assert_eq!(*wire.last().expect("есть"), address::TYPE_NONE);

        let (back, _) = Packet::decode(&wire[2..])
            .expect("разбирается")
            .expect("целиком");
        assert!(back.address.is_none());
    }

    #[test]
    fn a_half_read_packet_header_is_not_an_error() {
        let header = Packet {
            association: 1,
            packet: 1,
            fragments: 1,
            fragment: 0,
            size: 7,
            address: Some(SocketAddress::domain("dns.example.com", 53)),
        };
        let wire = header.encode().expect("собирается");

        for cut in 0..wire.len() - 2 {
            assert!(
                Packet::decode(&wire[2..2 + cut])
                    .expect("не сломано")
                    .is_none(),
                "обрезанный до {cut} байт заголовок разобрался целиком"
            );
        }
    }

    #[test]
    fn a_fragment_number_that_does_not_fit_is_refused() {
        // Кусков у датаграммы не бывает больше 255; молча обрезать номер
        // значит собрать её из не тех кусков.
        let header = Packet {
            association: 1,
            packet: 1,
            fragments: 255,
            fragment: 256,
            size: 1,
            address: None,
        };
        assert!(header.encode().is_err());
    }

    #[test]
    fn dissociate_and_heartbeat_are_as_short_as_they_look() {
        assert_eq!(dissociate(0x0102), [VERSION, CMD_DISSOCIATE, 0x01, 0x02]);
        assert_eq!(heartbeat(), [VERSION, CMD_HEARTBEAT]);
    }

    #[test]
    fn the_head_is_read_back() {
        let (command, used) = read_head(&heartbeat())
            .expect("не сломано")
            .expect("целиком");
        assert_eq!(command, CMD_HEARTBEAT);
        assert_eq!(used, 2);
    }

    #[test]
    fn a_wrong_version_says_it_is_not_tuic() {
        let err = read_head(&[0x04, 0x00]).expect_err("это не TUIC");
        assert!(err.to_string().contains("версия"), "{err}");
    }

    #[test]
    fn a_half_read_head_is_not_an_error() {
        assert!(read_head(&[]).expect("не сломано").is_none());
        assert!(read_head(&[VERSION]).expect("не сломано").is_none());
    }
}
