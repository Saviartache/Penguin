//! Адрес в записи SOCKS5: вид, адрес, порт.
//!
//! ```text
//! ┌──────┬───────────────────┬────────┐
//! │ ATYP │ адрес             │ порт   │
//! │ 1 Б  │ 4 / 1+n / 16 Б    │ 2 Б BE │
//! └──────┴───────────────────┴────────┘
//!   0x01 IPv4 · 0x03 домен · 0x04 IPv6
//! ```
//!
//! Домен в записи есть, и это важно: приложение, настроенное на прокси,
//! отдаёт имя как есть, не разрешая его. Именно поэтому у SOCKS5-режима нет
//! проблемы утечки DNS, которую в режиме TUN приходится решать отдельно.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{BufMut, BytesMut};
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
    let host = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).await?;
            Address::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets).await?;
            Address::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        ATYP_DOMAIN => {
            let len = reader.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            reader.read_exact(&mut name).await?;
            let name = String::from_utf8(name)
                .map_err(|_| InboundError::BadAddress("имя не в UTF-8".to_owned()))?;
            // Клиент вполне может прислать домен, который на самом деле
            // числовой адрес: так делают браузеры при вводе IP в строку.
            // Разбирать его как имя — значит потом безуспешно спрашивать DNS
            // про «1.2.3.4».
            name.parse().map_err(|_| InboundError::BadAddress(name))?
        }
        other => return Err(InboundError::UnsupportedAddressType(other)),
    };

    let port = reader.read_u16().await?;
    Ok(SocketAddress::new(host, port))
}

/// Разбирает адрес из буфера. Возвращает адрес и сколько байт занято.
///
/// Для UDP: там пакет приходит целиком, и читать его по байту из потока
/// незачем.
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
pub fn encode(address: &SocketAddress, buf: &mut BytesMut) {
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
            // Длина имени — один байт, длиннее 255 в SOCKS5 не выразить.
            // Обрезать нельзя: получился бы другой домен. Такое имя
            // недопустимо и по DNS (RFC 1035), так что до сюда не доходит.
            let bytes = name.as_bytes();
            let len = bytes.len().min(u8::MAX as usize);
            buf.put_u8(len as u8);
            buf.put_slice(&bytes[..len]);
        }
    }
    buf.put_u16(address.port);
}

/// Записывает адрес сокета — им отвечают на запрос.
pub fn encode_socket_addr(address: SocketAddr, buf: &mut BytesMut) {
    encode(&SocketAddress::from(address), buf);
}

#[cfg(test)]
mod tests {
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
        let address: SocketAddress = "example.com:443".parse().expect("адрес");
        let mut buf = BytesMut::new();
        encode(&address, &mut buf);

        let mut reader = std::io::Cursor::new(buf.to_vec());
        assert_eq!(read(&mut reader).await.expect("читается"), address);
    }

    #[tokio::test]
    async fn numeric_domain_becomes_an_address() {
        // Браузер, которому ввели IP в адресную строку, пришлёт его как
        // домен. Спрашивать про такой «домен» у DNS бессмысленно.
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
