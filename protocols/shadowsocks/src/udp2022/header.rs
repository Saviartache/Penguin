//! Байтовая раскладка тела датаграммы UDP 2022 — без шифрования, без сети.
//!
//! ```text
//! Клиент -> сервер (до шифрования, без 16-байтового заголовка сессии):
//!  TYPE(1) TIMESTAMP(8, BE) PADDING_LEN(2, BE) PADDING(...) ADDR(...) PAYLOAD(...)
//!
//! Сервер -> клиент:
//!  TYPE(1) TIMESTAMP(8, BE) CLIENT_SESSION_ID(8, BE) PADDING_LEN(2, BE) PADDING(...) ADDR(...) PAYLOAD(...)
//! ```
//!
//! Раскладка сверена построчно с `shadowsocks-rust`
//! (`relay/udprelay/aead_2022.rs`, ASCII-схема в начале файла,
//! `encrypt_client_payload_aead_2022`, `decrypt_server_payload_aead_2022`) и
//! независимо с `sing-shadowsocks2`
//! (`shadowaead_2022/method.go::WritePacket`, `readPacket`). Сам 16-байтовый
//! заголовок (идентификатор сессии, счётчик пакета) сюда не входит — им
//! занимается [`crate::udp2022::datagram`], потому что у AES-GCM и ChaCha он
//! устроен по-разному (см. документ [`crate::udp2022::cipher`]).

use penguin_core::address::SocketAddress;
use penguin_transport::addr::socks;

use crate::error::{ShadowsocksError, ShadowsocksResult};
use crate::header2022::{self, TYPE_CLIENT, TYPE_SERVER};

/// Собирает тело клиентской датаграммы (адрес назначения и данные).
pub fn build_client_body(
    now: u64,
    target: &SocketAddress,
    payload: &[u8],
) -> ShadowsocksResult<Vec<u8>> {
    let padding = header2022::padding_len(payload.is_empty());

    let mut out = Vec::with_capacity(
        1 + 8 + 2 + usize::from(padding) + socks::encoded_len(target) + payload.len(),
    );
    out.push(TYPE_CLIENT);
    out.extend_from_slice(&now.to_be_bytes());
    out.extend_from_slice(&padding.to_be_bytes());
    out.resize(out.len() + usize::from(padding), 0);
    socks::encode(target, &mut out).map_err(ShadowsocksError::from)?;
    out.extend_from_slice(payload);
    Ok(out)
}

/// Разбирает тело серверной датаграммы: проверяет тип и метку времени,
/// возвращает идентификатор сессии клиента (сервер обязан вернуть наш же),
/// адрес источника и полезную нагрузку.
pub fn parse_server_body(
    plain: &[u8],
    now: u64,
) -> ShadowsocksResult<(u64, SocketAddress, Vec<u8>)> {
    let Some((&kind, rest)) = plain.split_first() else {
        return Err(ShadowsocksError::malformed("датаграмма 2022 пуста"));
    };
    if kind != TYPE_SERVER {
        return Err(ShadowsocksError::malformed(format!(
            "датаграмма 2022: тип {kind:#04x} вместо ответа сервера"
        )));
    }

    let Some(timestamp) = rest.first_chunk::<8>() else {
        return Err(ShadowsocksError::malformed(
            "датаграмма 2022 оборвана на метке времени",
        ));
    };
    header2022::check_timestamp(u64::from_be_bytes(*timestamp), now)?;
    let rest = &rest[8..];

    let Some(session) = rest.first_chunk::<8>() else {
        return Err(ShadowsocksError::malformed(
            "датаграмма 2022 оборвана на идентификаторе сессии клиента",
        ));
    };
    let client_session_id = u64::from_be_bytes(*session);
    let rest = &rest[8..];

    let Some(padding_len) = rest.first_chunk::<2>() else {
        return Err(ShadowsocksError::malformed(
            "датаграмма 2022 оборвана на длине дополнения",
        ));
    };
    let padding_len = usize::from(u16::from_be_bytes(*padding_len));
    let rest = rest
        .get(2..)
        .ok_or_else(|| ShadowsocksError::malformed("датаграмма 2022 короче заголовка"))?;
    let rest = rest
        .get(padding_len..)
        .ok_or_else(|| ShadowsocksError::malformed("датаграмма 2022: дополнение длиннее пакета"))?;

    let Some((source, used)) = socks::decode(rest).map_err(ShadowsocksError::from)? else {
        return Err(ShadowsocksError::malformed(
            "адрес в датаграмме 2022 оборван",
        ));
    };

    Ok((client_session_id, source, rest[used..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SocketAddress {
        SocketAddress::domain("dns.example.com", 53)
    }

    #[test]
    fn the_client_body_carries_type_timestamp_and_address_in_order() {
        let body = build_client_body(1_700_000_000, &target(), b"query").expect("собирается");
        assert_eq!(body[0], TYPE_CLIENT);
        assert_eq!(
            u64::from_be_bytes(body[1..9].try_into().unwrap()),
            1_700_000_000
        );

        let padding_len = usize::from(u16::from_be_bytes(body[9..11].try_into().unwrap()));
        let after_padding = &body[11 + padding_len..];

        let mut expected_addr = Vec::new();
        socks::encode(&target(), &mut expected_addr).unwrap();
        assert_eq!(&after_padding[..expected_addr.len()], &expected_addr[..]);
        assert_eq!(&after_padding[expected_addr.len()..], b"query");
    }

    /// Собирает то, что расшифровала бы серверная датаграмма.
    fn server_plain(
        client_session_id: u64,
        timestamp: u64,
        target: &SocketAddress,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = vec![TYPE_SERVER];
        out.extend_from_slice(&timestamp.to_be_bytes());
        out.extend_from_slice(&client_session_id.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        socks::encode(target, &mut out).unwrap();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn a_well_formed_server_body_round_trips() {
        let plain = server_plain(42, 1_000, &target(), b"answer");
        let (session, source, payload) = parse_server_body(&plain, 1_005).expect("разбирается");
        assert_eq!(session, 42);
        assert_eq!(source, target());
        assert_eq!(payload, b"answer");
    }

    #[test]
    fn a_server_body_claiming_to_be_from_a_client_is_rejected() {
        let mut plain = server_plain(1, 1_000, &target(), b"x");
        plain[0] = TYPE_CLIENT;
        assert!(parse_server_body(&plain, 1_000).is_err());
    }

    #[test]
    fn a_stale_timestamp_is_rejected() {
        let plain = server_plain(1, 1_000, &target(), b"x");
        let err = parse_server_body(&plain, 2_000).expect_err("метка устарела");
        assert!(err.to_string().contains("час"), "{err}");
    }

    #[test]
    fn a_truncated_header_or_address_is_rejected_not_panicked_on() {
        // У полезной нагрузки нет своей длины — это весь остаток буфера, и
        // обрезанный ровно на границе перед ней пакет неотличим от пакета
        // без данных (см. `an_empty_payload_is_still_a_datagram` у AEAD).
        // Обрезан здесь должен быть заголовок или адрес — то, что и правда
        // разъезжается с форматом.
        let plain = server_plain(1, 1_000, &target(), b"payload");
        let header_and_address_len = plain.len() - b"payload".len();
        for cut in 0..header_and_address_len {
            assert!(
                parse_server_body(&plain[..cut], 1_000).is_err(),
                "длина {cut}"
            );
        }
    }

    #[test]
    fn a_body_cut_right_after_the_address_is_just_an_empty_payload() {
        let plain = server_plain(1, 1_000, &target(), b"payload");
        let header_and_address_len = plain.len() - b"payload".len();
        let (_, _, payload) =
            parse_server_body(&plain[..header_and_address_len], 1_000).expect("разбирается");
        assert!(payload.is_empty());
    }

    #[test]
    fn padding_is_skipped_without_being_returned() {
        // Дополнение реальное только тогда, когда `payload` пуст — здесь оно
        // подставлено руками, чтобы проверить именно пропуск, а не генератор.
        let mut plain = vec![TYPE_SERVER];
        plain.extend_from_slice(&1_000u64.to_be_bytes());
        plain.extend_from_slice(&7u64.to_be_bytes());
        plain.extend_from_slice(&3u16.to_be_bytes());
        plain.extend_from_slice(&[0xAA, 0xAA, 0xAA]);
        socks::encode(&target(), &mut plain).unwrap();
        plain.extend_from_slice(b"payload");

        let (_, _, payload) = parse_server_body(&plain, 1_000).expect("разбирается");
        assert_eq!(payload, b"payload");
    }
}
