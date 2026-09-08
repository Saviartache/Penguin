//! Байтовая раскладка заголовков TCP 2022 — без шифрования и без сети.
//!
//! ```text
//! Запрос (до шифрования):
//!  фиксированная часть:  TYPE(1) TIMESTAMP(8, BE) LENGTH(2, BE)
//!  переменная часть:     ADDR(...) PADDING_LEN(2, BE) PADDING(...)
//!
//! Ответ (до шифрования):
//!  фиксированная часть:  TYPE(1) TIMESTAMP(8, BE) REQUEST_SALT(...) LENGTH(2, BE)
//! ```
//!
//! Раскладка и порядок полей сверены построчно с двумя независимыми
//! источниками: `shadowsocks-rust`
//! (`crates/shadowsocks/src/relay/tcprelay/aead_2022.rs`, ASCII-схема в
//! начале файла, и `proxy_stream/protocol/v2.rs::Aead2022TcpRequestHeaderRef`)
//! и `sing-shadowsocks2` (`shadowaead_2022/method.go::writeRequest` и
//! `readResponse`). Обе шифруют фиксированную и переменную часть запроса
//! **двумя отдельными** кусками AEAD (со своим шагом счётчика на каждый), а
//! ответ — одним куском для фиксированной части и продолжают обычными
//! кусками данных дальше; это и делает [`crate::tcp2022::stream`].
//!
//! `LENGTH` в фиксированной части — это длина **следующего сразу за ней**
//! куска (переменной части запроса или первых данных ответа), а не отдельное
//! поле кадра: лишнего повторного поля длины здесь нет ни у одной из сторон.

use penguin_core::address::SocketAddress;
use penguin_transport::addr::socks;

use crate::error::{ShadowsocksError, ShadowsocksResult};
use crate::header2022::{self, TYPE_CLIENT, TYPE_SERVER};

/// Длина фиксированной части запроса: тип, метка времени, длина.
pub const REQUEST_FIXED_LEN: usize = 1 + 8 + 2;

/// Длина фиксированной части ответа при данной длине соли: тип, метка
/// времени, эхо запрошенной соли, длина.
pub fn response_fixed_len(salt_len: usize) -> usize {
    1 + 8 + salt_len + 2
}

/// Собирает открытый текст обоих кусков запроса.
///
/// Первый — фиксированная часть (тип, метка времени, длина второго куска);
/// второй — адрес назначения и случайное дополнение. У нас нет полезной
/// нагрузки, готовой к моменту рукопожатия (`ShadowsocksOutbound` отправляет
/// заголовок до того, как приложение прислало хоть байт), поэтому дополнение
/// всегда случайно на манер пустого кадра — так же решает и
/// `shadowsocks-rust` (`get_aead_2022_padding_size`).
pub fn build_request(target: &SocketAddress, now: u64) -> ShadowsocksResult<(Vec<u8>, Vec<u8>)> {
    let padding = header2022::padding_len(true);

    let mut variable = Vec::new();
    socks::encode(target, &mut variable).map_err(ShadowsocksError::from)?;
    variable.extend_from_slice(&padding.to_be_bytes());
    variable.resize(variable.len() + usize::from(padding), 0);

    let length = u16::try_from(variable.len()).map_err(|_| {
        ShadowsocksError::malformed(format!(
            "заголовок запроса 2022 длиной {} байт длиннее предела",
            variable.len()
        ))
    })?;

    let mut fixed = Vec::with_capacity(REQUEST_FIXED_LEN);
    fixed.push(TYPE_CLIENT);
    fixed.extend_from_slice(&now.to_be_bytes());
    fixed.extend_from_slice(&length.to_be_bytes());

    Ok((fixed, variable))
}

/// Разбирает расшифрованную фиксированную часть ответа.
///
/// Возвращает длину куска данных, который сразу следует за этой частью.
/// `our_salt` — соль, которую отправили мы: сервер обязан вернуть её же, и
/// несовпадение означает, что ответ пришёл не на наш запрос.
pub fn decode_response_fixed(plain: &[u8], our_salt: &[u8], now: u64) -> ShadowsocksResult<u16> {
    if plain.len() != response_fixed_len(our_salt.len()) {
        return Err(ShadowsocksError::malformed(
            "заголовок ответа 2022: длина не сходится",
        ));
    }

    let Some((&kind, rest)) = plain.split_first() else {
        return Err(ShadowsocksError::malformed("заголовок ответа 2022 пуст"));
    };
    if kind != TYPE_SERVER {
        return Err(ShadowsocksError::malformed(format!(
            "заголовок ответа 2022: тип {kind:#04x} вместо ответа сервера"
        )));
    }

    let Some(timestamp) = rest.first_chunk::<8>() else {
        return Err(ShadowsocksError::malformed(
            "заголовок ответа 2022 оборван на метке времени",
        ));
    };
    header2022::check_timestamp(u64::from_be_bytes(*timestamp), now)?;

    let rest = &rest[8..];
    let (echoed_salt, rest) = rest.split_at(our_salt.len());
    if echoed_salt != our_salt {
        return Err(ShadowsocksError::malformed(
            "заголовок ответа 2022: сервер подтвердил не ту соль — ответ не на наш запрос",
        ));
    }

    let Some(length) = rest.first_chunk::<2>() else {
        return Err(ShadowsocksError::malformed(
            "заголовок ответа 2022 оборван на длине",
        ));
    };
    Ok(u16::from_be_bytes(*length))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SocketAddress {
        SocketAddress::domain("example.com", 443)
    }

    #[test]
    fn the_request_is_laid_out_in_the_order_the_reference_names() {
        let (fixed, variable) = build_request(&target(), 1_700_000_000).expect("собирается");

        assert_eq!(fixed.len(), REQUEST_FIXED_LEN);
        assert_eq!(fixed[0], TYPE_CLIENT);
        assert_eq!(
            u64::from_be_bytes(fixed[1..9].try_into().unwrap()),
            1_700_000_000
        );
        assert_eq!(
            usize::from(u16::from_be_bytes(fixed[9..11].try_into().unwrap())),
            variable.len()
        );

        // Адрес — в начале переменной части, ровно то, что даёт общая запись.
        let mut expected_addr = Vec::new();
        socks::encode(&target(), &mut expected_addr).unwrap();
        assert_eq!(&variable[..expected_addr.len()], &expected_addr[..]);
    }

    #[test]
    fn the_padding_length_field_matches_the_padding_actually_appended() {
        let (_, variable) = build_request(&target(), 0).expect("собирается");

        let mut expected_addr = Vec::new();
        socks::encode(&target(), &mut expected_addr).unwrap();
        let after_addr = &variable[expected_addr.len()..];

        let padding_len = u16::from_be_bytes(after_addr[..2].try_into().unwrap());
        assert_eq!(after_addr.len() - 2, usize::from(padding_len));
    }

    /// Собирает то, что расшифровала бы фиксированная часть ответа сервера.
    fn response_plain(request_salt: &[u8], timestamp: u64, length: u16) -> Vec<u8> {
        let mut out = vec![TYPE_SERVER];
        out.extend_from_slice(&timestamp.to_be_bytes());
        out.extend_from_slice(request_salt);
        out.extend_from_slice(&length.to_be_bytes());
        out
    }

    #[test]
    fn a_well_formed_response_round_trips() {
        let salt = [7u8; 32];
        let plain = response_plain(&salt, 1_000, 123);
        let length = decode_response_fixed(&plain, &salt, 1_005).expect("разбирается");
        assert_eq!(length, 123);
    }

    #[test]
    fn a_response_with_the_wrong_echoed_salt_is_rejected() {
        let salt = [7u8; 32];
        let other = [9u8; 32];
        let plain = response_plain(&other, 1_000, 1);
        assert!(decode_response_fixed(&plain, &salt, 1_000).is_err());
    }

    #[test]
    fn a_response_claiming_to_be_from_a_client_is_rejected() {
        let salt = [1u8; 16];
        let mut plain = response_plain(&salt, 1_000, 1);
        plain[0] = TYPE_CLIENT;
        assert!(decode_response_fixed(&plain, &salt, 1_000).is_err());
    }

    #[test]
    fn a_stale_timestamp_names_the_clock_skew() {
        let salt = [1u8; 16];
        let plain = response_plain(&salt, 1_000, 1);
        let err = decode_response_fixed(&plain, &salt, 2_000).expect_err("метка устарела");
        assert!(err.to_string().contains("час"), "{err}");
    }

    #[test]
    fn a_truncated_response_is_rejected_not_panicked_on() {
        let salt = [1u8; 16];
        let plain = response_plain(&salt, 1_000, 1);
        for cut in 0..plain.len() {
            assert!(decode_response_fixed(&plain[..cut], &salt, 1_000).is_err());
        }
    }
}
