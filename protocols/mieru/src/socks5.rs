//! Внутри туннеля Mieru — обычный SOCKS5.
//!
//! У самого протокола Mieru нет поля адреса назначения: сегменты несут
//! только сырые байты сессии (см. документ крейта). Клиент `mita` — это
//! сервер SOCKS5, до которого достаёт туннель, и адрес назначения передаётся
//! ему так же, как передал бы его локальный SOCKS5-клиент: приветствие,
//! выбор способа опознания, запрос `CONNECT`. Опознание внутри тоннеля не
//! нужно — сервер уже опознал нас по ключу, — поэтому клиент предлагает
//! единственный способ, «без опознания».
//!
//! Разбор здесь только на запись и на то, что не требует чтения переменной
//! длины по частям (RFC 1928, §3–6). Само чтение ответа с проводом ведёт
//! `outbound`, потому что длина адреса в ответе неизвестна заранее.

use penguin_core::address::SocketAddress;
use penguin_transport::addr::socks;

use crate::error::{MieruError, MieruResult};

/// Версия SOCKS5.
pub const VERSION: u8 = 0x05;
/// Способ опознания «без опознания».
pub const METHOD_NO_AUTH: u8 = 0x00;
/// Сервер не принял ни одного предложенного способа.
pub const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
/// Команда `CONNECT`.
pub const CMD_CONNECT: u8 = 0x01;
/// Длина порта в ответе и в запросе.
pub const PORT_LEN: usize = 2;

/// Приветствие клиента: версия, одна метода — без опознания.
pub fn greeting() -> [u8; 3] {
    [VERSION, 1, METHOD_NO_AUTH]
}

/// Разбирает выбор способа опознания сервером.
pub fn parse_method_selection(bytes: [u8; 2]) -> MieruResult<()> {
    if bytes[0] != VERSION {
        return Err(MieruError::malformed(format!(
            "версия SOCKS5 внутри туннеля: {}",
            bytes[0]
        )));
    }
    match bytes[1] {
        METHOD_NO_AUTH => Ok(()),
        METHOD_NONE_ACCEPTABLE => Err(MieruError::malformed(
            "сервер Mieru не принял способ опознания «без опознания»",
        )),
        other => Err(MieruError::malformed(format!(
            "сервер Mieru потребовал незнакомый способ опознания {other:#04x}"
        ))),
    }
}

/// Собирает запрос `CONNECT` к цели.
pub fn connect_request(target: &SocketAddress) -> MieruResult<Vec<u8>> {
    let mut out = vec![VERSION, CMD_CONNECT, 0x00];
    socks::encode(target, &mut out)?;
    Ok(out)
}

/// Заголовок ответа на `CONNECT`: код результата и тип адреса, который за
/// ним последует.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyHead {
    /// Код результата RFC 1928, §6. `0` — успех.
    pub rep: u8,
    /// Тип адреса, идущего дальше.
    pub atyp: u8,
}

/// Разбирает первые четыре байта ответа: версия, код, резерв, тип адреса.
pub fn parse_reply_head(bytes: [u8; 4]) -> MieruResult<ReplyHead> {
    if bytes[0] != VERSION {
        return Err(MieruError::malformed(format!(
            "версия SOCKS5 внутри туннеля: {}",
            bytes[0]
        )));
    }
    Ok(ReplyHead {
        rep: bytes[1],
        atyp: bytes[3],
    })
}

/// Длина адреса в ответе, если она известна по одному только типу.
///
/// `Ok(None)` — тип домена: перед именем идёт ещё байт длины, и его нужно
/// прочитать отдельно, прежде чем знать, сколько читать дальше.
pub fn fixed_address_len(atyp: u8) -> MieruResult<Option<usize>> {
    match atyp {
        socks::ATYP_IPV4 => Ok(Some(4)),
        socks::ATYP_IPV6 => Ok(Some(16)),
        socks::ATYP_DOMAIN => Ok(None),
        other => Err(MieruError::malformed(format!(
            "неизвестный тип адреса {other:#04x} в ответе сервера Mieru"
        ))),
    }
}

/// Код результата означает успех.
pub fn rep_is_success(rep: u8) -> bool {
    rep == 0
}

/// Человекочитаемая причина кода результата (RFC 1928, §6).
pub fn describe_rep(rep: u8) -> &'static str {
    match rep {
        0 => "успех",
        1 => "общая ошибка сервера",
        2 => "запрещено правилами сервера",
        3 => "сеть недостижима",
        4 => "хост недостижим",
        5 => "в соединении отказано",
        6 => "TTL истёк",
        7 => "команда не поддерживается",
        8 => "тип адреса не поддерживается",
        _ => "неизвестная причина",
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn the_greeting_offers_only_no_auth() {
        assert_eq!(greeting(), [0x05, 0x01, 0x00]);
    }

    #[test]
    fn a_selection_of_no_auth_is_accepted() {
        parse_method_selection([0x05, METHOD_NO_AUTH]).expect("принимается");
    }

    #[test]
    fn a_refusal_to_pick_any_method_is_an_error() {
        // `0xff` значит «ни один из предложенных не годится» — здесь это
        // означает, что сервер не наш, а не то, что нужно опознание.
        assert!(parse_method_selection([0x05, METHOD_NONE_ACCEPTABLE]).is_err());
    }

    #[test]
    fn a_demand_for_a_different_method_is_an_error() {
        // Мы предложили только «без опознания»; выбор чего-то ещё значит,
        // что на связи не тот сервер.
        assert!(parse_method_selection([0x05, 0x02]).is_err());
    }

    #[test]
    fn the_connect_request_carries_the_target_address() {
        let target = SocketAddress::ip(Ipv4Addr::new(203, 0, 113, 5).into(), 443);
        let request = connect_request(&target).expect("собирается");
        assert_eq!(
            request,
            [0x05, 0x01, 0x00, 0x01, 203, 0, 113, 5, 0x01, 0xBB]
        );
    }

    #[test]
    fn success_is_recognised_by_a_zero_code() {
        assert!(rep_is_success(0));
        for rep in 1..=8 {
            assert!(!rep_is_success(rep));
        }
    }

    #[test]
    fn a_domain_reply_needs_one_more_length_byte() {
        assert_eq!(fixed_address_len(socks::ATYP_IPV4).unwrap(), Some(4));
        assert_eq!(fixed_address_len(socks::ATYP_IPV6).unwrap(), Some(16));
        assert_eq!(fixed_address_len(socks::ATYP_DOMAIN).unwrap(), None);
        assert!(fixed_address_len(0x07).is_err());
    }
}
