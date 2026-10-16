//! Датаграммы: расширенный `CONNECT` и содержимое датаграммы HTTP/3.
//!
//! ```text
//!  Context ID (i) = 0 ‖ адрес SOCKS5 ‖ данные
//! ```
//!
//! Context ID — как в RFC 9298; Quarter Stream ID — дело HTTP/3 ([`datagram`] для сервера).

use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_transport::addr::socks;
use penguin_transport::varint;

use crate::error::PingwinResult;

pub use penguin_transport::h3::datagram;

/// `:protocol` запроса канала.
pub const PROTOCOL: &str = "connect-udp";

/// `:path` запроса канала.
pub const PATH: &str = "/.well-known/pingwin/udp";

/// Единственный Context ID.
const CONTEXT: u8 = 0;

/// Собирает содержимое датаграммы.
pub fn encode(target: &SocketAddress, data: &[u8]) -> PingwinResult<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + socks::encoded_len(target) + data.len());
    encode_into(target, data, &mut out)?;
    Ok(out)
}

/// Как [`encode`], но в переиспользуемый буфер (очищается).
pub fn encode_into(target: &SocketAddress, data: &[u8], out: &mut Vec<u8>) -> PingwinResult<()> {
    out.clear();
    out.push(CONTEXT);
    socks::encode(target, out)?;
    out.extend_from_slice(data);
    Ok(())
}

/// Разбирает содержимое; `None` — чужой контекст или нет адреса.
pub fn decode(mut payload: Bytes) -> Option<(SocketAddress, Bytes)> {
    let (context, used) = varint::try_decode(&payload)?;
    if context != u64::from(CONTEXT) {
        return None;
    }
    let (address, consumed) = socks::decode(&payload[used..]).ok()??;
    Some((address, payload.split_off(used + consumed)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_goes_in_front_of_the_data() {
        let target = SocketAddress::domain("example.com", 53);
        let raw = encode(&target, b"query").expect("собирается");
        assert_eq!(raw[0], 0, "Context ID");

        let (address, data) = decode(Bytes::from(raw)).expect("разбирается");
        assert_eq!(address, target);
        assert_eq!(&data[..], b"query");
    }

    #[test]
    fn a_recorded_datagram_is_read() {
        // 0, IPv4 1.2.3.4, порт 53, данные «hi».
        let raw = Bytes::from_static(&[0, 1, 1, 2, 3, 4, 0, 53, b'h', b'i']);
        let (address, data) = decode(raw).expect("разбирается");
        assert_eq!(address.to_wire(), "1.2.3.4:53");
        assert_eq!(&data[..], b"hi");
    }

    #[test]
    fn a_foreign_context_or_a_cut_address_is_dropped() {
        assert!(decode(Bytes::from_static(&[1, 1, 1, 2, 3, 4, 0, 53])).is_none());
        assert!(decode(Bytes::from_static(&[0, 1, 1, 2])).is_none());
        assert!(decode(Bytes::new()).is_none());
    }
}
