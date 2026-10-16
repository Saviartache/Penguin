//! Кадры UDP-мультиплексора `_udp2`: разбор и сборка байт без сети (`AGENTS.md`, §2.3).
//!
//! Формат разный в две стороны, поэтому функции раздельные.
//!
//! Кадр клиента (`PROTOCOL.md`, §6.3):
//!
//! ```text
//! +--------+----------+------+-----------+------+--------+---------+---------+
//! | Length |  SrcAddr | SrcP |  DstAddr  | DstP | AppLen | AppName | Payload |
//! |   4    |    16    |  2   |    16     |  2   |   1    |    L    |    N    |
//! +--------+----------+------+-----------+------+--------+---------+---------+
//! ```
//!
//! Кадр сервера (`PROTOCOL.md`, §6.4) — без имени приложения:
//!
//! ```text
//! +--------+----------+------+-----------+------+---------+
//! | Length |  SrcAddr | SrcP |  DstAddr  | DstP | Payload |
//! |   4    |    16    |  2   |    16     |  2   |    N    |
//! +--------+----------+------+-----------+------+---------+
//! ```
//!
//! `Length` считает байты после себя (`lib/src/http_udp_codec.rs::encode_packet`/
//! `process_client_length`).
//!
//! # Расхождение с текстом спецификации
//!
//! §11.2: IPv4, если первые 12 байт нулевые «и это не `::1`». Эталон
//! (`lib/src/net_utils.rs::get_fixed_size_ip`) исключения не делает: `::1`
//! читается как `0.0.0.1`. Повторяем эталон (`AGENTS.md`, 8.2).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{TrustTunnelError, TrustTunnelResult};

/// Длина поля длины.
const LENGTH_LEN: usize = 4;
/// Длина адресного поля (IPv4 дополняется двенадцатью нулями).
const ADDR_LEN: usize = 16;
/// Длина поля порта.
const PORT_LEN: usize = 2;
/// Длина поля длины имени приложения.
const APP_NAME_LEN_LEN: usize = 1;

/// Заголовок клиентского кадра после `Length`: два адреса, два порта, байт длины имени.
const CLIENT_HEADER_LEN: usize = 2 * (ADDR_LEN + PORT_LEN) + APP_NAME_LEN_LEN;
/// То же для серверного кадра (без имени приложения).
const SERVER_HEADER_LEN: usize = 2 * (ADDR_LEN + PORT_LEN);

/// Верхняя граница длины кадра: `MAX_UDP_PAYLOAD_SIZE` эталона (`lib/src/net_utils.rs`).
pub const MAX_DECLARED_LENGTH: usize = 65536 - 20 - 8;

/// Кадр от сервера; `destination` — синтетический адрес сессии (`PROTOCOL.md`, §6.5, см. [`super::session`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFrame {
    /// Кто отправил данные.
    pub source: SocketAddr,
    /// Кому предназначены.
    pub destination: SocketAddr,
    /// Данные.
    pub payload: Bytes,
}

/// Кадр клиента с именем приложения (здесь всегда пустое, см. [`crate::connect`]).
pub fn encode_client_frame(
    source: SocketAddr,
    destination: SocketAddr,
    app_name: &str,
    payload: &[u8],
) -> TrustTunnelResult<Bytes> {
    let app_name = app_name.as_bytes();
    let app_name_len = u8::try_from(app_name.len()).map_err(|_| {
        TrustTunnelError::malformed(format!(
            "имя приложения длиной {} байт не помещается в байт",
            app_name.len()
        ))
    })?;

    let body_len = CLIENT_HEADER_LEN + app_name.len() + payload.len();
    let mut buf = BytesMut::with_capacity(LENGTH_LEN + body_len);
    buf.put_u32(body_len as u32);
    put_fixed_ip(&mut buf, source.ip());
    buf.put_u16(source.port());
    put_fixed_ip(&mut buf, destination.ip());
    buf.put_u16(destination.port());
    buf.put_u8(app_name_len);
    buf.put_slice(app_name);
    buf.put_slice(payload);
    Ok(buf.freeze())
}

/// Разбирает кадр сервера с начала буфера: кадр и число разобранных байт; `Ok(None)` — не хватает данных.
pub fn decode_server_frame(bytes: &[u8]) -> TrustTunnelResult<Option<(ServerFrame, usize)>> {
    let Some(length_field) = bytes.first_chunk::<LENGTH_LEN>() else {
        return Ok(None);
    };
    let body_len = u32::from_be_bytes(*length_field) as usize;

    if body_len < SERVER_HEADER_LEN {
        return Err(TrustTunnelError::malformed(format!(
            "длина кадра ({body_len}) меньше заголовка ({SERVER_HEADER_LEN})"
        )));
    }
    if body_len > MAX_DECLARED_LENGTH {
        return Err(TrustTunnelError::malformed(format!(
            "длина кадра ({body_len}) больше, чем бывает у настоящей датаграммы"
        )));
    }

    let total = LENGTH_LEN + body_len;
    if bytes.len() < total {
        return Ok(None);
    }

    let mut header = &bytes[LENGTH_LEN..LENGTH_LEN + SERVER_HEADER_LEN];
    let source = SocketAddr::new(get_fixed_ip(&mut header), header.get_u16());
    let destination = SocketAddr::new(get_fixed_ip(&mut header), header.get_u16());

    let payload = Bytes::copy_from_slice(&bytes[LENGTH_LEN + SERVER_HEADER_LEN..total]);
    Ok(Some((
        ServerFrame {
            source,
            destination,
            payload,
        },
        total,
    )))
}

/// Пишет адрес, дополняя IPv4 12 нулями слева (`PROTOCOL.md`, §1.3, §6.3).
fn put_fixed_ip(buf: &mut BytesMut, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            buf.put_slice(&[0u8; 12]);
            buf.put_slice(&ip.octets());
        }
        IpAddr::V6(ip) => buf.put_slice(&ip.octets()),
    }
}

/// Читает 16 байт адреса; IPv4 — по нулям в начале (как эталон).
fn get_fixed_ip(buf: &mut &[u8]) -> IpAddr {
    let mut raw = [0u8; ADDR_LEN];
    raw.copy_from_slice(&buf[..ADDR_LEN]);
    buf.advance(ADDR_LEN);

    if raw[..12].iter().all(|&b| b == 0) {
        let mut octets = [0u8; 4];
        octets.copy_from_slice(&raw[12..]);
        IpAddr::V4(Ipv4Addr::from(octets))
    } else {
        IpAddr::V6(Ipv6Addr::from(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    #[test]
    fn a_client_frame_round_trips_through_the_fixed_fields() {
        let source = v4(10, 0, 0, 5, 54321);
        let destination = v4(203, 0, 113, 7, 53);
        let encoded =
            encode_client_frame(source, destination, "penguin", b"hello").expect("собирается");

        // Ручной разбор как у сервера (`http_udp_codec.rs::process_client_fixed_header`).
        let body_len = u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize;
        assert_eq!(body_len, encoded.len() - 4);

        let mut rest = &encoded[4..];
        assert_eq!(get_fixed_ip(&mut rest), source.ip());
        assert_eq!(rest.get_u16(), source.port());
        assert_eq!(get_fixed_ip(&mut rest), destination.ip());
        assert_eq!(rest.get_u16(), destination.port());
        let app_len = rest.get_u8() as usize;
        assert_eq!(app_len, "penguin".len());
        assert_eq!(&rest[..app_len], b"penguin");
        assert_eq!(&rest[app_len..], b"hello");
    }

    #[test]
    fn an_empty_application_name_is_legal() {
        let encoded = encode_client_frame(v4(1, 2, 3, 4, 1), v4(5, 6, 7, 8, 2), "", b"x")
            .expect("собирается");
        let app_len_offset = 4 + CLIENT_HEADER_LEN - 1;
        assert_eq!(encoded[app_len_offset], 0);
    }

    #[test]
    fn a_server_frame_has_no_application_name_field() {
        // Кадр сервера вручную, как `http_udp_codec.rs::Encoder::encode_packet`: без байта длины имени.
        let source = v4(198, 51, 100, 9, 8080);
        let destination = v4(192, 0, 2, 1, 4444);
        let payload = b"reply";

        let mut wire = BytesMut::new();
        wire.put_u32((SERVER_HEADER_LEN + payload.len()) as u32);
        put_fixed_ip(&mut wire, source.ip());
        wire.put_u16(source.port());
        put_fixed_ip(&mut wire, destination.ip());
        wire.put_u16(destination.port());
        wire.put_slice(payload);

        let (frame, used) = decode_server_frame(&wire)
            .expect("разбирается")
            .expect("целиком");
        assert_eq!(frame.source, source);
        assert_eq!(frame.destination, destination);
        assert_eq!(&frame.payload[..], payload);
        assert_eq!(used, wire.len());
    }

    #[test]
    fn decoding_a_client_frame_as_a_server_frame_shifts_the_payload() {
        // Кадр клиента, прочитанный как серверный, молча сдвигает данные.
        let source = v4(10, 0, 0, 1, 1111);
        let destination = v4(10, 0, 0, 2, 2222);
        let client_wire =
            encode_client_frame(source, destination, "app", b"DATA").expect("собирается");

        let (frame, _) = decode_server_frame(&client_wire)
            .expect("разбирается")
            .expect("целиком");
        // Адреса разбираются верно, а «данные» начинаются с байта длины имени и самого имени.
        assert_eq!(frame.source, source);
        assert_eq!(frame.destination, destination);
        assert_ne!(
            &frame.payload[..],
            b"DATA",
            "данные обязаны были сдвинуться"
        );
        assert_eq!(&frame.payload[..], b"\x03appDATA");
    }

    #[test]
    fn a_length_shorter_than_the_header_is_rejected() {
        let mut wire = BytesMut::new();
        wire.put_u32(4);
        wire.put_slice(&[0u8; 4]);
        assert!(decode_server_frame(&wire).is_err());
    }

    #[test]
    fn an_absurd_length_is_rejected_without_waiting_for_it() {
        let mut wire = BytesMut::new();
        wire.put_u32(u32::MAX);
        assert!(decode_server_frame(&wire).is_err());
    }

    #[test]
    fn a_frame_split_across_reads_is_not_an_error() {
        let source = v4(1, 1, 1, 1, 10);
        let destination = v4(2, 2, 2, 2, 20);
        let mut wire = BytesMut::new();
        wire.put_u32(SERVER_HEADER_LEN as u32 + 3);
        put_fixed_ip(&mut wire, source.ip());
        wire.put_u16(source.port());
        put_fixed_ip(&mut wire, destination.ip());
        wire.put_u16(destination.port());
        wire.put_slice(b"abc");

        for cut in 0..wire.len() {
            assert!(
                decode_server_frame(&wire[..cut])
                    .expect("не сломано")
                    .is_none(),
                "обрезанный до {cut} байт кадр разобрался целиком"
            );
        }
        let (frame, used) = decode_server_frame(&wire)
            .expect("разбирается")
            .expect("целиком");
        assert_eq!(used, wire.len());
        assert_eq!(&frame.payload[..], b"abc");
    }

    #[test]
    fn ipv4_round_trips_without_padding_bytes_leaking() {
        let mut buf = BytesMut::new();
        put_fixed_ip(&mut buf, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(buf.len(), ADDR_LEN);
        let mut slice = &buf[..];
        assert_eq!(
            get_fixed_ip(&mut slice),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn ipv6_round_trips() {
        let ip = IpAddr::V6("2001:db8::1".parse().unwrap());
        let mut buf = BytesMut::new();
        put_fixed_ip(&mut buf, ip);
        let mut slice = &buf[..];
        assert_eq!(get_fixed_ip(&mut slice), ip);
    }

    #[test]
    fn loopback_v6_is_decoded_as_the_reference_does_not_the_spec() {
        // Расхождение из шапки модуля: `::1` читается как IPv4.
        let loopback_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let mut buf = BytesMut::new();
        put_fixed_ip(&mut buf, loopback_v6);
        let mut slice = &buf[..];
        assert_eq!(
            get_fixed_ip(&mut slice),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
            "эталон здесь не отличает `::1` от `0.0.0.1` — а этот код повторяет эталон"
        );
    }
}
