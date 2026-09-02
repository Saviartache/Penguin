//! UDP ASSOCIATE и инкапсуляция датаграмм.
//!
//! ```text
//! ┌────────┬──────┬──────┬────────┬────────┐
//! │ RSV 2Б │ FRAG │ ATYP │ АДРЕС  │ ДАННЫЕ │
//! └────────┴──────┴──────┴────────┴────────┘
//! ```
//!
//! Управляющее соединение TCP при этом остаётся открытым, и его закрытие
//! означает конец сессии. Это единственный способ понять, что клиент ушёл: у
//! UDP закрытия нет, и без такой привязки сокет висел бы вечно.
//!
//! `FRAG` — фрагментация на уровне SOCKS5. Её не реализует почти никто, и
//! отправлять фрагменты клиенты не пробуют; принимать их мы не беремся и
//! отбрасываем явно, а не делаем вид, что заголовок кончился.

use bytes::{BufMut, BytesMut};
use penguin_core::address::SocketAddress;

use super::address;

/// Разобранная датаграмма от клиента.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    /// Куда клиент просит отправить.
    pub target: SocketAddress,
    /// Что отправить.
    pub payload: &'a [u8],
}

/// Разбирает датаграмму от клиента.
///
/// `None` — датаграмма повреждена или фрагментирована. Ответить об этом
/// некому: обратной связи у UDP нет.
pub fn decode(datagram: &[u8]) -> Option<Packet<'_>> {
    // RSV(2) + FRAG(1) — минимум перед адресом.
    if datagram.len() < 3 {
        return None;
    }
    if datagram[2] != 0 {
        // Фрагмент. Собирать его мы не умеем, и молча отдать кусок наверх
        // хуже, чем выбросить: приложение получило бы обрезанные данные.
        return None;
    }

    let (target, consumed) = address::decode(&datagram[3..])?;
    let payload = datagram.get(3 + consumed..)?;
    Some(Packet { target, payload })
}

/// Собирает датаграмму для клиента.
pub fn encode(source: &SocketAddress, payload: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(3 + 262 + payload.len());
    buf.put_u16(0); // RSV
    buf.put_u8(0); // FRAG: не фрагментировано
    address::encode(source, &mut buf);
    buf.put_slice(payload);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let source: SocketAddress = "1.2.3.4:53".parse().expect("адрес");
        let encoded = encode(&source, b"hello");
        let decoded = decode(&encoded).expect("разбирается");
        assert_eq!(decoded.target, source);
        assert_eq!(decoded.payload, b"hello");
    }

    #[test]
    fn round_trips_domain_target() {
        let target: SocketAddress = "example.com:443".parse().expect("адрес");
        let encoded = encode(&target, b"payload");
        assert_eq!(decode(&encoded).expect("разбирается").target, target);
    }

    #[test]
    fn rejects_fragments() {
        let mut encoded = encode(&"1.2.3.4:53".parse().expect("адрес"), b"x");
        encoded[2] = 1;
        // Отдать кусок наверх значило бы подсунуть приложению обрезанные данные.
        assert!(decode(&encoded).is_none());
    }

    #[test]
    fn rejects_truncated() {
        let encoded = encode(&"1.2.3.4:53".parse().expect("адрес"), b"payload");
        for cut in 0..encoded.len() - b"payload".len() {
            assert!(
                decode(&encoded[..cut]).is_none(),
                "разобрал обрезанное на {cut}"
            );
        }
    }

    #[test]
    fn empty_payload_is_valid() {
        // Датаграмма нулевой длины — законная вещь, и её надо доставить.
        let encoded = encode(&"1.2.3.4:53".parse().expect("адрес"), b"");
        let decoded = decode(&encoded).expect("разбирается");
        assert!(decoded.payload.is_empty());
    }
}
