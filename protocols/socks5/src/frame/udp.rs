//! Заголовок датаграммы SOCKS5 (RFC 1928, §7).
//!
//! ```text
//! +-----+------+------+----------+----------+----------+
//! | RSV | FRAG | ATYP |   ADDR   |   PORT   |   DATA   |
//! +-----+------+------+----------+----------+----------+
//! |  2  |  1   |  1   | 4/16/1+n |    2     | сколько  |
//! +-----+------+------+----------+----------+----------+
//! ```
//!
//! Адрес назначения стоит на **каждой** посылке — поэтому один канал
//! обслуживает всю UDP-сессию приложения, сколько бы адресатов у неё ни было.
//!
//! Дробление (`FRAG`) не поддерживается, и это осознанно. В RFC оно есть, в
//! жизни — почти нигде: реализации прокси собирают части по-разному, а
//! датаграмма, собранная неверно, доходит до приложения испорченной, и
//! отличить это от потери невозможно. Пришедший кусок отбрасывается — так же,
//! как потерянный пакет, к чему UDP и готов.

use bytes::Bytes;
use penguin_core::address::SocketAddress;

use crate::error::Socks5Result;
use crate::frame::address;

/// Длина неизменной части заголовка: два байта резерва и байт дробления.
const PREFIX: usize = 3;

/// Собирает датаграмму для отправки на выданный прокси адрес.
pub fn encode(target: &SocketAddress, payload: &[u8]) -> Socks5Result<Vec<u8>> {
    // С запасом на самый длинный адрес: тип, длина, 255 байт имени и порт.
    let mut out = Vec::with_capacity(PREFIX + 259 + payload.len());
    out.extend_from_slice(&[0, 0, 0]);
    address::encode(target, &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

/// Разбирает пришедшую датаграмму.
///
/// `Ok(None)` — датаграмма дроблёная или короче заголовка: и то и другое
/// означает «данных отсюда взять нельзя», а не «соединение сломано».
pub fn decode(datagram: &[u8]) -> Socks5Result<Option<(SocketAddress, Bytes)>> {
    let Some(rest) = datagram.get(PREFIX..) else {
        return Ok(None);
    };
    // Байт дробления: всё, что не ноль, — часть, а не датаграмма.
    if datagram.get(2).copied().unwrap_or_default() != 0 {
        return Ok(None);
    }

    let Some((source, consumed)) = address::decode(rest)? else {
        return Ok(None);
    };
    let Some(payload) = rest.get(consumed..) else {
        return Ok(None);
    };
    Ok(Some((source, Bytes::copy_from_slice(payload))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(raw: &str, port: u16) -> SocketAddress {
        SocketAddress::ip(raw.parse().expect("адрес"), port)
    }

    #[test]
    fn a_datagram_survives_the_round_trip() {
        let target = SocketAddress::domain("example.com", 53);
        let wrapped = encode(&target, b"\x00\x01payload").expect("собирается");

        let (back, payload) = decode(&wrapped).expect("разбирается").expect("целиком");
        assert_eq!(back, target);
        assert_eq!(&payload[..], b"\x00\x01payload");
    }

    #[test]
    fn the_reserved_bytes_are_zero() {
        // Прокси вправе отбросить датаграмму, в которой они не нули.
        let wrapped = encode(&SocketAddress::domain("example.com", 53), b"x").expect("собирается");
        assert_eq!(&wrapped[..3], &[0, 0, 0]);
    }

    #[test]
    fn a_fragment_is_dropped_not_reassembled() {
        // Собранная неверно датаграмма доходит до приложения испорченной, и
        // отличить это от потери невозможно.
        let mut wrapped = encode(&ip("203.0.113.5", 53), b"x").expect("собирается");
        wrapped[2] = 1;
        assert!(decode(&wrapped).expect("не сломано").is_none());
    }

    #[test]
    fn a_short_datagram_is_dropped_quietly() {
        // Обрезанная датаграмма — это не «сломанный прокси», а потерянный
        // пакет: взять из неё нечего, и рвать из-за неё канал незачем.
        let full = encode(&ip("203.0.113.5", 53), b"x").expect("собирается");
        // Заголовок без данных обрезком не считается: пустая датаграмма
        // законна, и её проверяет соседний тест.
        let header = full.len() - 1;

        for cut in 0..header {
            assert!(
                decode(&full[..cut]).expect("не сломано").is_none(),
                "обрезанная до {cut} байт датаграмма разобралась целиком"
            );
        }
    }

    #[test]
    fn an_empty_payload_is_still_a_datagram() {
        // Пустая датаграмма — законная: её шлют, например, чтобы открыть NAT.
        let wrapped = encode(&ip("203.0.113.5", 53), b"").expect("собирается");
        let (_, payload) = decode(&wrapped).expect("разбирается").expect("целиком");
        assert!(payload.is_empty());
    }

    #[test]
    fn a_broken_address_type_is_an_error_not_a_drop() {
        // Тип адреса, которого не бывает, означает не «часть датаграммы», а
        // «на том конце не SOCKS5».
        let mut datagram = vec![0, 0, 0, 0x07];
        datagram.extend_from_slice(&[1, 2, 3, 4, 0, 53]);
        assert!(decode(&datagram).is_err());
    }
}
