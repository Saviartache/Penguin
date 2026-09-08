//! Запись на проводе: пять байт заголовка и AEAD внутри.
//!
//! ```text
//! +------+---------+--------+-----------------------------+
//! | 0x17 | 0x0303  | длина  |  AEAD(кадры) + метка 16 байт |
//! +------+---------+--------+-----------------------------+
//! |  1   |    2    |   2    |            длина             |
//! +------+---------+--------+-----------------------------+
//! ```
//!
//! # Почему заголовок именно такой
//!
//! Это заголовок записи данных TLS 1.3, байт в байт. После `ServerHello` и
//! `ChangeCipherSpec` настоящий TLS 1.3 не показывает наружу **ничего**,
//! кроме таких записей: ни типов сообщений, ни длин рукопожатия — всё
//! зашифровано. Значит, поток из таких записей неотличим от настоящего
//! разговора TLS 1.3 не потому, что мы удачно подобрали маскировку, а потому,
//! что смотреть больше не на что.
//!
//! Длина при этом открыта — как и у настоящего TLS. Прячет её не запись, а
//! дополнение ([`crate::wire::padding`]): именно оно делает первые записи
//! непохожими на «маленький запрос, большой ответ».
//!
//! # Про счётчик
//!
//! Нонс не пишется на провод вовсе: он считается обеими сторонами
//! ([`penguin_transport::aead::Cipher`]). Пропущенная или
//! переставленная запись поэтому не «испортит один кадр», а оборвёт
//! соединение — и это правильно: переставить записи может только тот, кто
//! правит поток.

use penguin_transport::aead::{Cipher, TAG_LEN};

use crate::error::{PingwinError, PingwinResult};

/// Запись несёт данные. Тот же байт, что у TLS 1.3.
pub const CONTENT_DATA: u8 = 0x17;

/// Запись несёт сообщение рукопожатия.
pub const CONTENT_HANDSHAKE: u8 = 0x16;

/// Запись смены шифра — та самая, которую TLS 1.3 шлёт только ради мидлбоксов.
pub const CONTENT_CHANGE_CIPHER_SPEC: u8 = 0x14;

/// Версия в заголовке записи данных.
pub const VERSION_DATA: u16 = 0x0303;

/// Версия в заголовке самой первой записи — так делает каждый настоящий
/// клиент (см. `penguin_utls::record`).
pub const VERSION_FIRST: u16 = 0x0301;

/// Длина заголовка записи.
pub const HEADER_LEN: usize = 5;

/// Наибольшая длина тела записи. Столько же у настоящего TLS.
pub const MAX_BODY: usize = 1 << 14;

/// Сколько открытого текста помещается в одну запись.
pub const MAX_PLAIN: usize = MAX_BODY - TAG_LEN;

/// Запись смены шифра целиком — шесть байт, всегда одни и те же.
///
/// Отправляется обеими сторонами ради одного: без неё поток отличается от
/// настоящего TLS 1.3 в режиме совместимости, а в этом режиме работают все.
pub const CHANGE_CIPHER_SPEC: [u8; 6] = [CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];

/// Собирает заголовок записи.
pub fn header(content_type: u8, version: u16, len: usize) -> PingwinResult<[u8; HEADER_LEN]> {
    let len = u16::try_from(len).map_err(|_| PingwinError::Oversized(len))?;
    if usize::from(len) > MAX_BODY {
        return Err(PingwinError::Oversized(usize::from(len)));
    }
    let version = version.to_be_bytes();
    let len = len.to_be_bytes();
    Ok([content_type, version[0], version[1], len[0], len[1]])
}

/// Разбирает заголовок записи: тип и длину тела.
///
/// Версию не проверяем: у настоящего TLS в этом поле лежит то `0x0301`, то
/// `0x0303`, и требовать одно значение значило бы отвергать собственное
/// приветствие.
pub fn parse_header(bytes: &[u8; HEADER_LEN]) -> PingwinResult<(u8, usize)> {
    let len = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    if len > MAX_BODY {
        return Err(PingwinError::malformed(format!(
            "запись длиной {len} байт — больше, чем бывает у TLS"
        )));
    }
    Ok((bytes[0], len))
}

/// Зашифровывает кадры и дописывает готовую запись в `out`.
pub fn seal(cipher: &mut Cipher, plain: &[u8], out: &mut Vec<u8>) -> PingwinResult<()> {
    if plain.len() > MAX_PLAIN {
        return Err(PingwinError::Oversized(plain.len()));
    }
    let sealed = cipher.seal(plain)?;
    out.extend_from_slice(&header(CONTENT_DATA, VERSION_DATA, sealed.len())?);
    out.extend_from_slice(&sealed);
    Ok(())
}

/// Расшифровывает тело записи на месте и возвращает длину открытого текста.
pub fn open(cipher: &mut Cipher, body: &mut [u8]) -> PingwinResult<usize> {
    if body.len() < TAG_LEN {
        return Err(PingwinError::malformed(
            "запись короче метки подлинности: на том конце не наш сервер",
        ));
    }
    Ok(cipher.open(body)?)
}

#[cfg(test)]
mod tests {
    use penguin_transport::aead::Algorithm;

    use super::*;

    fn cipher() -> Cipher {
        Cipher::new(Algorithm::Aes256Gcm, &[3u8; 32]).expect("ключ подходит")
    }

    #[test]
    fn a_record_starts_the_way_a_tls_data_record_starts() {
        // Побайтно: свой разбор согласился бы сам с собой при любой ошибке.
        let mut out = Vec::new();
        seal(&mut cipher(), b"ab", &mut out).expect("шифруется");
        assert_eq!(out[0], 0x17);
        assert_eq!(&out[1..3], &[0x03, 0x03]);
        assert_eq!(
            usize::from(u16::from_be_bytes([out[3], out[4]])),
            2 + TAG_LEN
        );
        assert_eq!(out.len(), HEADER_LEN + 2 + TAG_LEN);
    }

    #[test]
    fn what_is_sealed_opens_on_the_other_side() {
        let mut out = Vec::new();
        seal(&mut cipher(), b"payload", &mut out).expect("шифруется");

        let (content_type, len) =
            parse_header(out.first_chunk().expect("пять байт")).expect("разбирается");
        assert_eq!(content_type, CONTENT_DATA);

        let mut body = out[HEADER_LEN..HEADER_LEN + len].to_vec();
        let plain = open(&mut cipher(), &mut body).expect("расшифровывается");
        assert_eq!(&body[..plain], b"payload");
    }

    #[test]
    fn the_biggest_record_fits_and_the_next_one_does_not() {
        // Записать длиннее — значит объявить длину, которая не влезает в два
        // байта, и разъехаться с сервером на первой же записи.
        let mut out = Vec::new();
        seal(&mut cipher(), &vec![0; MAX_PLAIN], &mut out).expect("влезает");
        assert!(seal(&mut cipher(), &vec![0; MAX_PLAIN + 1], &mut Vec::new()).is_err());
    }

    #[test]
    fn a_record_longer_than_tls_allows_is_refused_before_reading_it() {
        // Иначе чужой сервер (или мусор) заставил бы выделить память по
        // объявленной длине — а объявить он может что угодно.
        assert!(parse_header(&[0x17, 0x03, 0x03, 0xff, 0xff]).is_err());
        let (_, len) = parse_header(&[0x17, 0x03, 0x03, 0x40, 0x00]).expect("ровно предел");
        assert_eq!(len, MAX_BODY);
    }

    #[test]
    fn a_record_shorter_than_the_tag_is_refused_without_panicking() {
        assert!(open(&mut cipher(), &mut [0u8; TAG_LEN - 1]).is_err());
    }

    #[test]
    fn the_change_cipher_spec_record_is_the_one_tls_sends() {
        assert_eq!(CHANGE_CIPHER_SPEC, [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    }
}
