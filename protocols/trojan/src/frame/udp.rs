//! Датаграмма внутри потока.
//!
//! ```text
//! +------+----------+----------+--------+------+----------+
//! | ATYP | DST.ADDR | DST.PORT | Length | CRLF |  данные  |
//! +------+----------+----------+--------+------+----------+
//! |  1   | сколько  |    2     |   2    |  2   | сколько  |
//! +------+----------+----------+--------+------+----------+
//! ```
//!
//! Адрес стоит на **каждой** посылке, поэтому один поток обслуживает всю
//! UDP-сессию приложения, сколько бы адресатов у неё ни было. Этим Trojan
//! отличается от VLESS, где адрес назван один раз в заголовке и на каждый
//! адрес нужен свой поток.
//!
//! # Зачем длина, если границы и так есть
//!
//! Их нет. Внутри — поток TLS, то есть байты без границ: две датаграммы,
//! отправленные подряд, приходят одним куском, а одна большая — тремя. Длина
//! и есть та граница, которую протокол восстанавливает; `CRLF` после неё —
//! проверка, что мы читаем заголовок, а не середину чужих данных.

use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_transport::addr::socks;

use crate::error::{TrojanError, TrojanResult};
use crate::frame::request::CRLF;

/// Наибольшая датаграмма, которую мы согласны принять.
///
/// Больше и не бывает: 65535 — предел самого UDP. Верить объявленной длине
/// без предела значит отдать памяти столько, сколько скажет тот конец.
pub const MAX_PAYLOAD: usize = 65_535;

/// Собирает датаграмму для отправки в поток.
pub fn encode(target: &SocketAddress, payload: &[u8]) -> TrojanResult<Vec<u8>> {
    let len = u16::try_from(payload.len()).map_err(|_| TrojanError::Oversized(payload.len()))?;

    let mut out = Vec::with_capacity(socks::encoded_len(target) + 4 + payload.len());
    socks::encode(target, &mut out)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&CRLF);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Читает датаграмму с начала среза.
///
/// Возвращает адрес отправителя, данные и число съеденных байт.
/// `Ok(None)` — пришло пока не всё; это не ошибка, а обычное дело в потоке.
pub fn decode(bytes: &[u8]) -> TrojanResult<Option<(SocketAddress, Bytes, usize)>> {
    let Some((source, used)) = socks::decode(bytes)? else {
        return Ok(None);
    };

    let Some(len) = bytes.get(used..).and_then(<[u8]>::first_chunk::<2>) else {
        return Ok(None);
    };
    let len = usize::from(u16::from_be_bytes(*len));

    let Some(crlf) = bytes.get(used + 2..).and_then(<[u8]>::first_chunk::<2>) else {
        return Ok(None);
    };
    // Не сошлось — значит, мы читаем не заголовок. Дальше в потоке смысла нет:
    // восстановить границу нечем, и притворяться, что пакет просто потерян,
    // означало бы отдавать приложению мусор до конца сессии.
    if *crlf != CRLF {
        return Err(TrojanError::malformed(
            "после длины датаграммы нет CRLF: поток разъехался",
        ));
    }

    let start = used + 4;
    let Some(payload) = bytes.get(start..start + len) else {
        return Ok(None);
    };
    Ok(Some((source, Bytes::copy_from_slice(payload), start + len)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(raw: &str, port: u16) -> SocketAddress {
        SocketAddress::ip(raw.parse().expect("адрес"), port)
    }

    #[test]
    fn a_datagram_survives_the_round_trip() {
        for target in [
            ip("203.0.113.5", 53),
            ip("2001:db8::1", 53),
            SocketAddress::domain("dns.example.com", 53),
        ] {
            let wrapped = encode(&target, b"\x00\x01payload").expect("собирается");
            let (back, payload, used) = decode(&wrapped).expect("разбирается").expect("целиком");

            assert_eq!(back, target);
            assert_eq!(&payload[..], b"\x00\x01payload");
            assert_eq!(used, wrapped.len(), "съедено не всё");
        }
    }

    #[test]
    fn the_bytes_are_where_the_protocol_says() {
        let wrapped = encode(&ip("203.0.113.5", 53), b"xy").expect("собирается");
        assert_eq!(
            wrapped,
            [
                0x01, 203, 0, 113, 5, 0x00, 0x35, 0x00, 0x02, 0x0D, 0x0A, b'x', b'y'
            ]
        );
    }

    #[test]
    fn two_datagrams_in_one_chunk_are_read_one_by_one() {
        // Внутри TLS границ нет: две посылки подряд приходят одним куском, и
        // разделяет их только объявленная длина.
        let first = encode(&ip("203.0.113.5", 53), b"one").expect("собирается");
        let second = encode(&ip("198.51.100.9", 5353), b"two").expect("собирается");
        let mut stream = first.clone();
        stream.extend_from_slice(&second);

        let (_, payload, used) = decode(&stream).expect("разбирается").expect("целиком");
        assert_eq!(&payload[..], b"one");
        assert_eq!(used, first.len());

        let (_, payload, used) = decode(&stream[used..])
            .expect("разбирается")
            .expect("целиком");
        assert_eq!(&payload[..], b"two");
        assert_eq!(used, second.len());
    }

    #[test]
    fn a_datagram_arriving_in_pieces_is_not_an_error() {
        // Одна датаграмма приходит тремя кусками — это обычное дело в потоке,
        // и объявлять поломкой надо не это.
        let full =
            encode(&SocketAddress::domain("dns.example.com", 53), b"payload").expect("собирается");

        for cut in 0..full.len() {
            assert!(
                decode(&full[..cut]).expect("не сломано").is_none(),
                "обрезанная до {cut} байт датаграмма разобралась целиком"
            );
        }
    }

    #[test]
    fn an_empty_payload_is_still_a_datagram() {
        let wrapped = encode(&ip("203.0.113.5", 53), b"").expect("собирается");
        let (_, payload, used) = decode(&wrapped).expect("разбирается").expect("целиком");
        assert!(payload.is_empty());
        assert_eq!(used, wrapped.len());
    }

    #[test]
    fn a_missing_crlf_stops_the_stream() {
        // Восстановить границу нечем: дальше по потоку всё будет мусором, и
        // отдавать его приложению хуже, чем оборвать сессию.
        let mut wrapped = encode(&ip("203.0.113.5", 53), b"xy").expect("собирается");
        wrapped[9] = b'!';
        assert!(decode(&wrapped).is_err());
    }

    #[test]
    fn a_datagram_too_big_to_announce_is_refused() {
        // Длина пишется двумя байтами; молча обрезать значит испортить данные
        // так, что приложение не узнает о потере.
        let huge = vec![0u8; MAX_PAYLOAD + 1];
        assert!(encode(&ip("203.0.113.5", 53), &huge).is_err());
    }
}
