//! Датаграмма внутри потока: адрес, длина, данные.
//!
//! ```text
//! +----------------------------+--------+---------+
//! |      адрес по SOCKS5       | длина  | данные  |
//! +----------------------------+--------+---------+
//! | тип(1) + хост + порт(2 BE) | 2 (BE) |  0..64K |
//! +----------------------------+--------+---------+
//! ```
//!
//! Байта сети здесь нет: он стоял один раз, в заголовке потока. Адрес же
//! повторяется на каждой посылке — в этом весь смысл: один поток обслуживает
//! сколько угодно адресатов, и сервер знает, куда слать, из самой посылки.
//!
//! Обратно приходит то же самое, без байта сети.

use penguin_core::address::SocketAddress;
use penguin_transport::addr::socks;

use crate::error::{JuicityError, JuicityResult};

/// Сколько данных помещается в одну датаграмму.
///
/// Длина пишется двумя байтами. Больше и не бывает: датаграмма UDP сама
/// длиннее не бывает.
pub const MAX_PAYLOAD: usize = u16::MAX as usize;

/// Наибольшая длина адреса: тип, байт длины, имя и порт.
pub const MAX_ADDRESS: usize = 1 + 1 + 255 + 2;

/// Собирает датаграмму для отправки.
pub fn seal(target: &SocketAddress, payload: &[u8]) -> JuicityResult<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD {
        return Err(JuicityError::Oversized(payload.len()));
    }

    let mut out = Vec::with_capacity(socks::encoded_len(target) + 2 + payload.len());
    socks::encode(target, &mut out)?;
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use penguin_transport::addr::socks::ATYP_IPV4;

    use super::*;

    #[test]
    fn the_datagram_is_address_length_payload() {
        let target = SocketAddress::ip("203.0.113.5".parse().unwrap(), 53);
        let sealed = seal(&target, "привет".as_bytes()).expect("собирается");

        let head = socks::encoded_len(&target);
        assert_eq!(sealed[0], ATYP_IPV4);
        assert_eq!(
            &sealed[head..head + 2],
            &("привет".len() as u16).to_be_bytes()
        );
        assert_eq!(&sealed[head + 2..], "привет".as_bytes());
    }

    #[test]
    fn there_is_no_network_byte_here() {
        // Он стоял один раз, в заголовке потока. Лишний байт впереди сдвинул
        // бы весь разбор на сервере.
        let sealed = seal(&SocketAddress::domain("a.io", 53), b"x").expect("собирается");
        assert_eq!(sealed[0], socks::ATYP_DOMAIN);
    }

    #[test]
    fn an_empty_datagram_is_still_a_datagram() {
        // Пустая датаграмма UDP законна, и терять её нельзя: ею проверяют
        // достижимость.
        let sealed = seal(&SocketAddress::domain("a.io", 53), &[]).expect("собирается");
        assert_eq!(&sealed[sealed.len() - 2..], &[0, 0]);
    }

    #[test]
    fn a_datagram_too_long_to_announce_is_refused() {
        let too_big = vec![0_u8; MAX_PAYLOAD + 1];
        let target = SocketAddress::domain("a.io", 53);
        assert!(seal(&target, &too_big).is_err());
        assert!(seal(&target, &too_big[..MAX_PAYLOAD]).is_ok());
    }
}
