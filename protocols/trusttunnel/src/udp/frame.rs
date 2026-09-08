//! Кадры UDP-мультиплексора `_udp2`: разбор и сборка байт, без сети и без
//! `tokio` (`AGENTS.md`, §2.3).
//!
//! Формат **разный в две стороны** — это главная ловушка протокола, и ради
//! неё у клиентских и серверных кадров разные структуры и разные функции
//! ниже, а не один разбиратель с флагом направления.
//!
//! Кадр клиента (`PROTOCOL.md`, §6.3 — там это «Client → Endpoint»):
//!
//! ```text
//! +--------+----------+------+-----------+------+--------+---------+---------+
//! | Length |  SrcAddr | SrcP |  DstAddr  | DstP | AppLen | AppName | Payload |
//! |   4    |    16    |  2   |    16     |  2   |   1    |    L    |    N    |
//! +--------+----------+------+-----------+------+--------+---------+---------+
//! ```
//!
//! Кадр сервера (`PROTOCOL.md`, §6.4 — «Endpoint → Client») — **без поля
//! имени приложения**:
//!
//! ```text
//! +--------+----------+------+-----------+------+---------+
//! | Length |  SrcAddr | SrcP |  DstAddr  | DstP | Payload |
//! |   4    |    16    |  2   |    16     |  2   |    N    |
//! +--------+----------+------+-----------+------+---------+
//! ```
//!
//! `Length` считает всё, что идёт **после** себя (сверено с эталоном,
//! `lib/src/http_udp_codec.rs::encode_packet`/`process_client_length`, не
//! только с текстом спецификации). Разобрать серверный кадр по клиентскому
//! формату — сдвиг на всю длину имени приложения, и данные поедут молча:
//! отсюда `an_application_name_field_only_exists_on_client_frames` в тестах
//! ниже.
//!
//! # Расхождение с текстом спецификации: определение IPv4
//!
//! §11.2 обещает: «адрес — IPv4, если первые 12 байт нулевые, **и это не
//! `::1`**». Эталон (`lib/src/net_utils.rs::get_fixed_size_ip`) этого
//! исключения не делает вовсе — проверяется только обнуление первых 12 байт.
//! Значит, настоящий сервер декодирует `::1` (`0000:...:0001`) как
//! `0.0.0.1`, а не как петлевой IPv6-адрес. Здесь код повторяет **эталон**,
//! а не текст документа (`AGENTS.md`, правило 8.2: при расхождении
//! спецификации с кодом верим коду): для наших синтетических адресов источника
//! (см. [`super::session`]) это и вовсе не заметно — они не используют `::1`
//! — но при разборе адреса, пришедшего от сервера, разница была бы видна.

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

/// Часть заголовка клиентского кадра после `Length`, без имени приложения и
/// данных: два адреса, два порта, байт длины имени.
const CLIENT_HEADER_LEN: usize = 2 * (ADDR_LEN + PORT_LEN) + APP_NAME_LEN_LEN;
/// То же для серверного кадра — имени приложения в нём нет вовсе.
const SERVER_HEADER_LEN: usize = 2 * (ADDR_LEN + PORT_LEN);

/// Верхняя граница объявленной в кадре длины.
///
/// Не из спецификации — своя защита. У эталона это ровно
/// `MAX_UDP_PAYLOAD_SIZE` (`lib/src/net_utils.rs`): наибольший УДП-пакет,
/// какой вообще существует в IP-сети (65536 − заголовок IPv4 − заголовок
/// UDP). Без этой границы повреждённое поле длины заставило бы разбор ждать
/// байты, которых никогда не придёт, вместо того чтобы сообщить об ошибке
/// сразу.
pub const MAX_DECLARED_LENGTH: usize = 65536 - 20 - 8;

/// Кадр, полученный от сервера: кто отправил, кому предназначен, что внутри.
///
/// `destination` — не наш локальный адрес в обычном смысле, а тот
/// синтетический адрес, который эта же сессия указала как источник в своих
/// исходящих кадрах (`PROTOCOL.md`, §6.5: сервер отслеживает «соединения» по
/// 4-элементному ключу и в ответе меняет источник с назначением местами).
/// Разбор по нему и связывает пришедший кадр с открывшей его сессией — см.
/// [`super::session`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFrame {
    /// Кто отправил данные — цель, которой сессия писала.
    pub source: SocketAddr,
    /// Кому эти данные предназначены — адрес нашей стороны на этом кадре.
    pub destination: SocketAddr,
    /// Данные.
    pub payload: Bytes,
}

/// Собирает кадр клиента: с полем имени приложения.
///
/// `app_name` в этом крейте всегда пуст (см. [`crate::connect`], пояснение
/// про `user-agent`) — архитектура клиента не доводит до протокола, какое
/// приложение породило пакет. Поле остаётся параметром, а не жёстко пустой
/// строкой, потому что пуста ровно **эта** реализация, а не формат: пустое
/// имя — легальное значение (длина `0`), а не заглушка мимо протокола.
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
    // `Length` считает всё, что идёт после этого поля, — не общую длину
    // кадра (сверено с `http_udp_codec.rs::process_client_length`, где
    // именно так проверяется нижняя граница).
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

/// Разбирает один кадр сервера с начала буфера.
///
/// `Ok(None)` — байтов пока не хватает: копите дальше и зовите снова. Кадр,
/// в отличие от кадра клиента, **не несёт поля имени приложения** — это и
/// есть ловушка, названная в шапке модуля.
///
/// Возвращает кадр и число разобранных байт — байты сверх этого числа
/// (начало следующего кадра) не трогаются.
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

/// Пишет адрес, дополняя IPv4 двенадцатью нулями слева (`PROTOCOL.md`, §1.3,
/// §6.3).
fn put_fixed_ip(buf: &mut BytesMut, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            buf.put_slice(&[0u8; 12]);
            buf.put_slice(&ip.octets());
        }
        IpAddr::V6(ip) => buf.put_slice(&ip.octets()),
    }
}

/// Читает шестнадцать байт адреса, определяя IPv4 по нулям в начале.
///
/// Повторяет эталон, а не текст спецификации — см. пояснение в шапке модуля.
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

        // Разбираем клиентский кадр вручную тем же способом, каким его читает
        // сервер (`http_udp_codec.rs::process_client_fixed_header`), чтобы
        // проверить именно раскладку, а не только то, что наш же декодер
        // соглашается сам с собой.
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
        // Пустое имя — законное значение (длина 0), а не отказ: этот крейт
        // не знает, какое приложение породило пакет, и посылает именно его.
        let encoded = encode_client_frame(v4(1, 2, 3, 4, 1), v4(5, 6, 7, 8, 2), "", b"x")
            .expect("собирается");
        let app_len_offset = 4 + CLIENT_HEADER_LEN - 1;
        assert_eq!(encoded[app_len_offset], 0);
    }

    #[test]
    fn a_server_frame_has_no_application_name_field() {
        // Ловушка, названная в задаче: серверный кадр короче клиентского на
        // всю длину имени приложения. Собираем кадр сервера вручную — ровно
        // так, как это делает `http_udp_codec.rs::Encoder::encode_packet` —
        // и убеждаемся, что наш разбор не ждёт байта длины имени, которого
        // в этом формате попросту нет.
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
        // Прямая демонстрация ловушки: если бы декодер сервера ошибочно
        // читал кадр клиента (с именем приложения) как серверный, данные
        // сдвинулись бы на длину имени и байт её длины — и уехали бы молча,
        // без единой ошибки разбора. Тест защищает от повторного изобретения
        // этой ошибки, а не от нынешнего кода: `decode_server_frame` кадр
        // клиента и так не видит, у него другой источник данных.
        let source = v4(10, 0, 0, 1, 1111);
        let destination = v4(10, 0, 0, 2, 2222);
        let client_wire =
            encode_client_frame(source, destination, "app", b"DATA").expect("собирается");

        let (frame, _) = decode_server_frame(&client_wire)
            .expect("разбирается")
            .expect("целиком");
        // Два адреса с портами разбираются правильно — раскладка этих полей
        // у обоих кадров совпадает. А вот «данные» на самом деле начинаются
        // с байта длины имени (3 — длина строки "app"), за которым идёт само
        // имя и только потом настоящая полезная нагрузка: три поля вместо
        // одного, склеенные в то, что декодер принял за один `payload`.
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
        wire.put_u32(4); // меньше SERVER_HEADER_LEN
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
        // Расхождение из шапки модуля, зафиксированное тестом: `::1` имеет
        // двенадцать нулевых байт впереди точно так же, как настоящий IPv4,
        // и эталон (в отличие от текста `PROTOCOL.md`, §11.2) не делает для
        // него исключения.
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
