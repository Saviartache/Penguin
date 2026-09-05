//! Заголовок запроса: версия, команда, список признаков.
//!
//! ```text
//! +-----+-------------+--------+----------+
//! | VER |  CMD/FLAGS  | FEALEN | FEATURES |
//! +-----+-------------+--------+----------+
//! |  1  |      1      |    2   |    VAR   |
//! +-----+-------------+--------+----------+
//! ```
//!
//! Взято из `github.com/go-gost/relay`, файл `relay.go` (структура кадра) и
//! `feature.go` (устройство признаков), ревизия `d323730` ветки `master` от
//! 2026-07-24. Признак — это `TYPE(1) LEN(2, BE) DATA` подряд, и сервер
//! читает их по типу, а не по месту: неважно, в каком порядке в письме стоят
//! адрес и пароль.
//!
//! # CMD и FLAGS в одном байте
//!
//! Младшие четыре бита — команда (`CmdConnect` = `0x01`), старший бит —
//! флаг [`FLAG_UDP`] (`0x80`): поток несёт UDP, а не TCP. Сам `relay.go`
//! называет флаг устаревшим («DEPRECATED by network feature»), но эталонный
//! клиент (`github.com/go-gost/x`, `connector/relay/connector.go`, ревизия
//! `fe9d9c9` от 2026-09-05, метод `Connect`) всё равно выставляет и флаг, и
//! признак `FeatureNetwork` одновременно — ради серверов, которые второе
//! ещё не понимают. Этот крейт делает то же самое: то, что называет
//! устаревшим сам код, всё равно посылает его собственный клиент, и первична
//! здесь эта строка кода, а не комментарий над ней.
//!
//! Команда `CmdBind` (`0x02`, настоящий `UDP ASSOCIATE`) и признак
//! `FeatureTunnel` этим крейтом не собираются — см. документ крейта
//! ([`crate`]) и [`crate::datagram`], почему.

use penguin_core::address::SocketAddress;
use penguin_transport::addr::socks;

use crate::error::{GostRelayError, GostRelayResult};

/// Версия протокола. Другой не было ни разу.
pub const VERSION: u8 = 0x01;

/// Открыть соединение до адреса назначения.
pub const CMD_CONNECT: u8 = 0x01;

/// Флаг в старшем бите байта `CMD/FLAGS`: поток несёт UDP.
pub const FLAG_UDP: u8 = 0x80;

/// Признак: имя и пароль.
const FEATURE_USER_AUTH: u8 = 0x01;
/// Признак: адрес назначения.
const FEATURE_ADDR: u8 = 0x02;
/// Признак: тип сети.
const FEATURE_NETWORK: u8 = 0x04;

/// Сеть — UDP, в записи признака [`FEATURE_NETWORK`].
const NETWORK_UDP: u16 = 0x0001;

/// Сколько байт умещает имя или пароль: длина в запросе — один байт.
const MAX_CREDENTIAL: usize = 0xFF;

/// Собирает запрос: заголовок и список признаков.
///
/// `auth` — имя и пароль, если сервер их спрашивает. `None`, если в
/// настройках профиля не задано ни то, ни другое: тогда признак не
/// посылается вовсе — точно так же эталонный клиент не шлёт его при
/// отсутствии настроенного `Auth` (`connector.go`, `if c.options.Auth != nil`).
pub fn build(
    cmd: u8,
    udp: bool,
    auth: Option<(&str, &str)>,
    target: &SocketAddress,
) -> GostRelayResult<Vec<u8>> {
    let mut features = Vec::new();

    // Порядок — тот же, что у `connector.go` для запроса с уже известным
    // адресом: сеть, потом имя-пароль, потом адрес. Сервер признаки не
    // упорядочивает и читает их по типу, так что порядок здесь — только
    // ради того, чтобы байты совпадали с эталоном буквально.
    if udp {
        push_feature(&mut features, FEATURE_NETWORK, &NETWORK_UDP.to_be_bytes());
    }
    if let Some((user, pass)) = auth {
        push_feature(&mut features, FEATURE_USER_AUTH, &user_auth(user, pass)?);
    }
    let mut addr = Vec::with_capacity(socks::encoded_len(target));
    socks::encode(target, &mut addr)?;
    push_feature(&mut features, FEATURE_ADDR, &addr);

    let len =
        u16::try_from(features.len()).map_err(|_| GostRelayError::Oversized(features.len()))?;

    let mut out = Vec::with_capacity(4 + features.len());
    out.push(VERSION);
    out.push(cmd);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&features);
    Ok(out)
}

/// Дописывает один признак: тип, длина, данные.
fn push_feature(out: &mut Vec<u8>, kind: u8, data: &[u8]) {
    out.push(kind);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// Признак имени и пароля: `ULEN(1) UNAME PLEN(1) PASSWD`.
///
/// # Расхождение в исходнике
///
/// Комментарий-таблица над `UserAuthFeature` в `feature.go` называет длину
/// пароля «1 to 255» байт, а строка сразу под ней — «0 to 255, 0 means no
/// password». Сам код `Encode`/`Decode` длину не проверяет вовсе и пропускает
/// пустой пароль свободно. «Код важнее прозы» здесь работает буквально:
/// расходятся не два источника, а сам источник сам с собой, и решает не
/// текст комментария, а то, что действительно делает `Encode`. Поэтому
/// пустые имя и пароль этот крейт тоже разрешает.
fn user_auth(user: &str, pass: &str) -> GostRelayResult<Vec<u8>> {
    if user.len() > MAX_CREDENTIAL {
        return Err(GostRelayError::config(format!(
            "имя длиной {} байт не помещается в один байт длины",
            user.len()
        )));
    }
    if pass.len() > MAX_CREDENTIAL {
        return Err(GostRelayError::config(format!(
            "пароль длиной {} байт не помещается в один байт длины",
            pass.len()
        )));
    }

    let mut out = Vec::with_capacity(2 + user.len() + pass.len());
    out.push(user.len() as u8);
    out.extend_from_slice(user.as_bytes());
    out.push(pass.len() as u8);
    out.extend_from_slice(pass.as_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SocketAddress {
        SocketAddress::ip("203.0.113.5".parse().unwrap(), 443)
    }

    #[test]
    fn a_plain_tcp_request_has_no_network_feature() {
        // Сеть TCP — умолчание сервера (`networkID.String()` на нуле), и
        // эталонный клиент для неё признак не шлёт вовсе.
        let bytes = build(CMD_CONNECT, false, None, &target()).expect("собирается");
        assert_eq!(bytes[0], VERSION);
        assert_eq!(bytes[1], CMD_CONNECT);

        // Один признак — адрес: TYPE=0x02, LEN, потом ATYP+ADDR+PORT.
        assert_eq!(bytes[4], FEATURE_ADDR);
    }

    #[test]
    fn the_udp_flag_and_the_network_feature_go_together() {
        // `relay.go` называет флаг устаревшим, но эталонный клиент шлёт оба
        // сигнала разом — этот тест проверяет именно то, что шлёт код.
        let bytes = build(CMD_CONNECT | FLAG_UDP, true, None, &target()).expect("собирается");
        assert_eq!(bytes[1], CMD_CONNECT | FLAG_UDP);
        assert_eq!(bytes[4], FEATURE_NETWORK);
        assert_eq!(&bytes[5..7], &[0x00, 0x02], "длина признака сети");
        assert_eq!(&bytes[7..9], &[0x00, 0x01], "NetworkUDP = 1");
    }

    #[test]
    fn auth_is_only_present_when_configured() {
        let without = build(CMD_CONNECT, false, None, &target()).expect("собирается");
        let with =
            build(CMD_CONNECT, false, Some(("bob", "secret")), &target()).expect("собирается");
        assert!(with.len() > without.len());

        // Признак имени и пароля стоит первым при отсутствии признака сети.
        assert_eq!(with[4], FEATURE_USER_AUTH);
    }

    #[test]
    fn an_empty_username_and_password_are_legal() {
        // Расхождение в `feature.go`: код разрешает нулевую длину, хотя
        // таблица в комментарии называет пароль обязательным. Здесь работает
        // код.
        let bytes = build(CMD_CONNECT, false, Some(("", "")), &target()).expect("собирается");
        assert_eq!(bytes[4], FEATURE_USER_AUTH);
        // ULEN=0, PLEN=0 — признак ровно из двух байт.
        assert_eq!(&bytes[5..7], &[0x00, 0x02]);
        assert_eq!(&bytes[7..9], &[0x00, 0x00]);
    }

    #[test]
    fn a_username_too_long_to_announce_is_refused() {
        let long = "a".repeat(256);
        assert!(build(CMD_CONNECT, false, Some((&long, "x")), &target()).is_err());
    }

    #[test]
    fn a_password_too_long_to_announce_is_refused() {
        let long = "a".repeat(256);
        assert!(build(CMD_CONNECT, false, Some(("x", &long)), &target()).is_err());
    }

    #[test]
    fn the_address_is_the_shared_socks_encoding() {
        // Совпадает с записью SOCKS5 буквально — своей у GOST Relay нет.
        let bytes = build(CMD_CONNECT, false, None, &target()).expect("собирается");
        let mut expected = Vec::new();
        socks::encode(&target(), &mut expected).unwrap();
        assert_eq!(&bytes[7..], &expected[..]);
    }

    #[test]
    fn a_domain_too_long_to_fit_is_refused() {
        let long = "a".repeat(256);
        assert!(build(CMD_CONNECT, false, None, &SocketAddress::domain(&long, 443)).is_err());
    }

    #[test]
    fn feature_length_is_the_bytes_after_the_four_byte_header() {
        let bytes = build(CMD_CONNECT, false, None, &target()).expect("собирается");
        let announced = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(announced, bytes.len() - 4);
    }
}
