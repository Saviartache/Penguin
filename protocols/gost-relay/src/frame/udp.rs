//! Датаграмма внутри потока-туннеля с флагом UDP: только длина и данные.
//!
//! ```text
//! +--------+----------+
//! | длина  |  данные  |
//! +--------+----------+
//! |   2    | сколько  |
//! +--------+----------+
//! ```
//!
//! Формат `github.com/go-gost/x` (ревизия `fe9d9c9` от 2026-09-05):
//! `connector/relay/conn.go` (`udpConn.Read`/`udpConn.Write` на стороне
//! клиента) и `handler/relay/connect.go` (тот же `udpConn` на стороне
//! сервера, см. документ в `handleConnect`). Двухбайтовая длина без знака,
//! big-endian, затем ровно столько байт данных. Адреса здесь нет — поток и
//! так связан с одним адресатом заголовком запроса
//! ([`crate::frame::request`]): `Cmd = CmdConnect | FLAG_UDP` с признаком
//! адреса назначения внутри.
//!
//! # Отличие от «настоящего» `UDP ASSOCIATE`
//!
//! У этого формата нет и не может быть чужого адреса внутри посылки — не
//! потому что его забыли добавить, а потому что весь смысл режима
//! `CmdConnect` в том, что адрес назван один раз, в заголовке. Формат
//! адресуемых посылок для режима `CmdBind` (`UDPHeader` из
//! `github.com/go-gost/gosocks5`) устроен иначе — там впереди датаграммы
//! идёт полный адрес получателя. Этот крейт его не собирает: сам режим
//! `CmdBind` не используется по причине, описанной в [`crate::datagram`].

use bytes::Bytes;

use crate::error::{GostRelayError, GostRelayResult};

/// Наибольшая датаграмма: длина пишется двумя байтами.
pub const MAX_PAYLOAD: usize = u16::MAX as usize;

/// Собирает датаграмму для отправки в поток.
pub fn encode(payload: &[u8]) -> GostRelayResult<Vec<u8>> {
    let len = u16::try_from(payload.len()).map_err(|_| GostRelayError::Oversized(payload.len()))?;

    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Читает датаграмму с начала среза.
///
/// Возвращает данные и число съеденных байт. `Ok(None)` — пришло пока не
/// всё; это не ошибка, а обычное дело в потоке.
pub fn decode(bytes: &[u8]) -> GostRelayResult<Option<(Bytes, usize)>> {
    let Some(raw) = bytes.first_chunk::<2>() else {
        return Ok(None);
    };
    let len = usize::from(u16::from_be_bytes(*raw));

    let Some(payload) = bytes.get(2..2 + len) else {
        return Ok(None);
    };
    Ok(Some((Bytes::copy_from_slice(payload), 2 + len)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_datagram_survives_the_round_trip() {
        let wrapped = encode(b"\x00\x01query").expect("собирается");
        let (payload, used) = decode(&wrapped).expect("разбирается").expect("целиком");
        assert_eq!(&payload[..], b"\x00\x01query");
        assert_eq!(used, wrapped.len());
    }

    #[test]
    fn the_length_comes_first_and_is_big_endian() {
        let wrapped = encode(b"xy").expect("собирается");
        assert_eq!(wrapped, [0x00, 0x02, b'x', b'y']);
    }

    #[test]
    fn two_datagrams_in_one_chunk_are_read_one_by_one() {
        let mut stream = encode(b"one").expect("собирается");
        stream.extend_from_slice(&encode(b"two").expect("собирается"));

        let (payload, used) = decode(&stream).expect("разбирается").expect("целиком");
        assert_eq!(&payload[..], b"one");
        let (payload, _) = decode(&stream[used..])
            .expect("разбирается")
            .expect("целиком");
        assert_eq!(&payload[..], b"two");
    }

    #[test]
    fn a_datagram_arriving_in_pieces_is_not_an_error() {
        let full = encode(b"payload").expect("собирается");
        for cut in 0..full.len() {
            assert!(
                decode(&full[..cut]).expect("не сломано").is_none(),
                "обрезанная до {cut} байт датаграмма разобралась целиком"
            );
        }
    }

    #[test]
    fn an_empty_payload_is_still_a_datagram() {
        let wrapped = encode(b"").expect("собирается");
        let (payload, used) = decode(&wrapped).expect("разбирается").expect("целиком");
        assert!(payload.is_empty());
        assert_eq!(used, 2);
    }

    #[test]
    fn a_datagram_too_big_to_announce_is_refused() {
        let huge = vec![0u8; MAX_PAYLOAD + 1];
        assert!(encode(&huge).is_err());
    }

    #[test]
    fn trailing_bytes_after_one_datagram_are_left_alone() {
        // Датаграммы приходят подряд одна за другой: съесть чужой хвост
        // значило бы потерять начало следующей.
        let mut wrapped = encode(b"first").expect("собирается");
        let header = wrapped.len();
        wrapped.extend_from_slice(b"second-not-yet-a-frame");

        let (_, used) = decode(&wrapped).expect("разбирается").expect("целиком");
        assert_eq!(used, header);
    }
}
