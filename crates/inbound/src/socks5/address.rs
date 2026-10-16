//! Адрес в записи SOCKS5: `ATYP` (0x01 IPv4, 0x03 домен, 0x04 IPv6), адрес, порт BE.
//!
//! Домен приходит как есть, без разрешения, поэтому утечки DNS нет.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::BufMut;
use penguin_core::address::{Address, SocketAddress};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{InboundError, InboundResult};

/// Вид адреса: IPv4.
pub const ATYP_IPV4: u8 = 0x01;
/// Вид адреса: доменное имя.
pub const ATYP_DOMAIN: u8 = 0x03;
/// Вид адреса: IPv6.
pub const ATYP_IPV6: u8 = 0x04;

/// Читает адрес из потока.
pub async fn read<R>(reader: &mut R) -> InboundResult<SocketAddress>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let atyp = reader.read_u8().await?;
    read_after_type(reader, atyp).await
}

/// Читает адрес и порт после уже прочитанного `ATYP`; по одному чтению на вид.
pub async fn read_after_type<R>(reader: &mut R, atyp: u8) -> InboundResult<SocketAddress>
where
    R: AsyncRead + Unpin + ?Sized,
{
    match atyp {
        ATYP_IPV4 => {
            let mut raw = [0u8; 6];
            reader.read_exact(&mut raw).await?;
            let [a, b, c, d, hi, lo] = raw;
            let host = Address::Ip(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
            Ok(SocketAddress::new(host, u16::from_be_bytes([hi, lo])))
        }
        ATYP_IPV6 => {
            let mut raw = [0u8; 18];
            reader.read_exact(&mut raw).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&raw[..16]);
            let host = Address::Ip(IpAddr::V6(Ipv6Addr::from(octets)));
            Ok(SocketAddress::new(
                host,
                u16::from_be_bytes([raw[16], raw[17]]),
            ))
        }
        ATYP_DOMAIN => {
            let len = usize::from(reader.read_u8().await?);
            let mut raw = [0u8; 257];
            reader.read_exact(&mut raw[..len + 2]).await?;
            let name = std::str::from_utf8(&raw[..len])
                .map_err(|_| InboundError::BadAddress("имя не в UTF-8".to_owned()))?;
            // Браузер присылает введённый IP как домен.
            let host = name
                .parse()
                .map_err(|_| InboundError::BadAddress(name.to_owned()))?;
            Ok(SocketAddress::new(
                host,
                u16::from_be_bytes([raw[len], raw[len + 1]]),
            ))
        }
        other => Err(InboundError::UnsupportedAddressType(other)),
    }
}

/// Разбирает адрес из буфера (UDP). Возвращает адрес и число занятых байт.
pub fn decode(buf: &[u8]) -> Option<(SocketAddress, usize)> {
    let atyp = *buf.first()?;
    let (host, consumed) = match atyp {
        ATYP_IPV4 => {
            let octets: [u8; 4] = buf.get(1..5)?.try_into().ok()?;
            (Address::Ip(IpAddr::V4(Ipv4Addr::from(octets))), 5)
        }
        ATYP_IPV6 => {
            let octets: [u8; 16] = buf.get(1..17)?.try_into().ok()?;
            (Address::Ip(IpAddr::V6(Ipv6Addr::from(octets))), 17)
        }
        ATYP_DOMAIN => {
            let len = *buf.get(1)? as usize;
            let name = std::str::from_utf8(buf.get(2..2 + len)?).ok()?;
            (name.parse().ok()?, 2 + len)
        }
        _ => return None,
    };

    let port_bytes: [u8; 2] = buf.get(consumed..consumed + 2)?.try_into().ok()?;
    let port = u16::from_be_bytes(port_bytes);
    Some((SocketAddress::new(host, port), consumed + 2))
}

/// Записывает адрес.
pub fn encode<B: BufMut>(address: &SocketAddress, buf: &mut B) {
    match &address.host {
        Address::Ip(IpAddr::V4(v4)) => {
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&v4.octets());
        }
        Address::Ip(IpAddr::V6(v6)) => {
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&v6.octets());
        }
        Address::Domain(name) => {
            buf.put_u8(ATYP_DOMAIN);
            // Длиннее 255 в SOCKS5 не выразить; по RFC 1035 такого имени не бывает.
            let bytes = name.as_bytes();
            let len = bytes.len().min(u8::MAX as usize);
            buf.put_u8(len as u8);
            buf.put_slice(&bytes[..len]);
        }
    }
    buf.put_u16(address.port);
}

/// Записывает адрес сокета — им отвечают на запрос.
pub fn encode_socket_addr<B: BufMut>(address: SocketAddr, buf: &mut B) {
    encode(&SocketAddress::from(address), buf);
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    fn round_trip(address: SocketAddress) {
        let mut buf = BytesMut::new();
        encode(&address, &mut buf);
        let (decoded, consumed) = decode(&buf).expect("разбирается");
        assert_eq!(decoded, address);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn round_trips_all_kinds() {
        round_trip("1.2.3.4:443".parse().expect("адрес"));
        round_trip("[2001:db8::1]:8443".parse().expect("адрес"));
        round_trip("example.com:80".parse().expect("адрес"));
    }

    #[tokio::test]
    async fn reads_from_stream() {
        for text in ["example.com:443", "1.2.3.4:80", "[2001:db8::1]:8443"] {
            let address: SocketAddress = text.parse().expect("адрес");
            let mut buf = BytesMut::new();
            encode(&address, &mut buf);

            let mut reader = std::io::Cursor::new(buf.to_vec());
            assert_eq!(read(&mut reader).await.expect("читается"), address);
        }
    }

    #[tokio::test]
    async fn numeric_domain_becomes_an_address() {
        let mut buf = BytesMut::new();
        buf.put_u8(ATYP_DOMAIN);
        buf.put_u8(7);
        buf.put_slice(b"1.2.3.4");
        buf.put_u16(443);

        let mut reader = std::io::Cursor::new(buf.to_vec());
        let parsed = read(&mut reader).await.expect("читается");
        assert!(parsed.host.as_ip().is_some(), "остался доменом: {parsed:?}");
    }

    #[tokio::test]
    async fn rejects_unknown_address_type() {
        let mut reader = std::io::Cursor::new(vec![0x09, 1, 2, 3, 4, 0, 80]);
        assert!(matches!(
            read(&mut reader).await,
            Err(InboundError::UnsupportedAddressType(0x09))
        ));
    }

    #[test]
    fn decode_rejects_truncated() {
        let address: SocketAddress = "example.com:80".parse().expect("адрес");
        let mut buf = BytesMut::new();
        encode(&address, &mut buf);
        for cut in 0..buf.len() {
            assert!(
                decode(&buf[..cut]).is_none(),
                "разобрал обрезанный буфер длиной {cut}"
            );
        }
    }
}
