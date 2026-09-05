//! Кадр TCP: длина под своей меткой, кусок под своей, нонс общий на оба.
//!
//! ```text
//!  ──► [шифр(длина)+метка] [шифр(кусок)+метка] [шифр(длина)+метка] ...
//!       ^^^^^^^^^^^^^^^^^^
//!       18 байт: 2 байта длины + 16 байт метки
//! ```
//!
//! Самый первый кусок, который отправляет клиент, — не данные приложения, а
//! `Unix Timestamp (4 байта) + DST Address`: адрес назначения в записи SOCKS5
//! ([`penguin_transport::addr::socks`]) и метка времени перед ним. Дальше
//! кадры уже несут то, что читает и пишет приложение.
//!
//! # Предел куска
//!
//! Эталон (`streamclient.go`/`streamserver.go`) держит буфер ровно в 2048
//! байт на TCP-направление (`x.BP2048`) и ни байтом больше. Кусок данных,
//! который в него не поместится вместе с обеими метками и полем длины, сервер
//! никогда не примет — не потому, что запрещает протокол (поле длины —
//! шестнадцать бит, туда влезло бы куда больше), а потому, что его буфер
//! физически не резиновый. Отсюда [`MAX_PAYLOAD`] — она меньше, чем позволяет
//! поле, и это осознанный выбор в пользу совместимости с настоящим сервером, а
//! не теоретического предела формата.
//!
//! # Про метку времени
//!
//! Она обязана быть **чётной** секундой Unix-времени — это то, чем сервер
//! отличает обычный TCP-поток от «UDP поверх TCP» (тот же кадр, но с нечётной
//! меткой). Мы не делаем «UDP поверх TCP», но обязаны соблюдать чётность:
//! иначе сервер примет наш TCP-поток за чужой режим и раскодирует его
//! неправильно с первого же байта.
//!
//! Сервер отвергает запрос, если его собственные часы ушли вперёд больше чем
//! на [`CLOCK_TOLERANCE_SECS`] относительно присланной метки (`streamserver.go`:
//! `time.Now().Unix()-i > 60`). Заметьте направление: метка **из будущего**
//! сервером не проверяется вовсе — отвергается только та, что отстала.

use penguin_core::address::SocketAddress;
use penguin_transport::addr::socks;

use crate::error::{BrookError, BrookResult};
use crate::frame::cipher::{Cipher, TAG_LEN, sealed_len};

/// Сколько байт занимает поле длины в открытом виде.
const LENGTH_FIELD: usize = 2;

/// Сколько байт занимает зашифрованное поле длины: два байта плюс метка.
pub const LENGTH_FRAME: usize = LENGTH_FIELD + TAG_LEN;

/// Буфер эталона на TCP-направление. Больше он в сокет не читает и не пишет.
const SERVER_BUFFER: usize = 2048;

/// Наибольший кусок данных, какой примет настоящий сервер.
///
/// `SERVER_BUFFER` минус зашифрованная длина минус метка данных.
pub const MAX_PAYLOAD: usize = SERVER_BUFFER - LENGTH_FRAME - TAG_LEN;

/// Насколько сервер терпит отставание присланных часов, в секундах.
///
/// Взято из `streamserver.go` и `packetserverconn.go` (ревизия `5cd13ef`):
/// оба места проверяют ровно `time.Now().Unix()-i > 60`. Опережение сервером
/// не проверяется вовсе, отсюда и однобокая формулировка ошибки в
/// [`crate::error::BrookError::HandshakeRejected`].
pub const CLOCK_TOLERANCE_SECS: i64 = 60;

/// Метка времени для обычного TCP-потока: секунда Unix-времени, округлённая
/// вверх до чётной.
///
/// Округление — не про допуск часов, а про то, как сервер отличает этот режим
/// от «UDP поверх TCP» (та же метка, но нечётная). Мы такого режима не
/// реализуем, но обязаны соблюдать эту чётность, иначе попадём в чужую ветку
/// разбора на сервере.
pub fn tcp_timestamp(now_unix: u64) -> u32 {
    let seconds = now_unix as u32;
    if seconds.is_multiple_of(2) {
        seconds
    } else {
        seconds.wrapping_add(1)
    }
}

/// Первый кусок клиента: метка времени и адрес назначения.
pub fn first_fragment(now_unix: u64, target: &SocketAddress) -> BrookResult<Vec<u8>> {
    let mut out = Vec::with_capacity(4 + socks::encoded_len(target));
    out.extend_from_slice(&tcp_timestamp(now_unix).to_be_bytes());
    socks::encode(target, &mut out).map_err(BrookError::from)?;
    Ok(out)
}

/// Шифрует один кусок: длину отдельным сообщением, данные — следующим.
///
/// Нонс шифра двигается дважды — так же, как у эталона (`streamclient.go`,
/// `Write`): один раз под длину, один раз под данные, и оба раза он разный.
pub fn seal_fragment(cipher: &mut Cipher, plain: &[u8]) -> BrookResult<Vec<u8>> {
    if plain.len() > MAX_PAYLOAD {
        return Err(BrookError::Oversized(plain.len()));
    }
    let length = plain.len() as u16;

    let mut out = cipher.seal(&length.to_be_bytes())?;
    out.extend_from_slice(&cipher.seal(plain)?);
    debug_assert_eq!(out.len(), LENGTH_FRAME + sealed_len(plain.len()));
    Ok(out)
}

/// Расшифровывает длину, уже прочитанную с провода.
///
/// `frame` — ровно [`LENGTH_FRAME`] байт: зашифрованные два байта плюс метка.
/// Возвращает длину следующего куска данных.
pub fn open_length(cipher: &mut Cipher, frame: &mut [u8]) -> BrookResult<u16> {
    let plain_len = cipher.open(frame)?;
    let bytes = frame
        .get(..plain_len)
        .and_then(<[u8]>::first_chunk::<LENGTH_FIELD>)
        .ok_or_else(|| BrookError::malformed("длина куска не на месте"))?;
    Ok(u16::from_be_bytes(*bytes))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::frame::nonce::Nonce;

    fn cipher(nonce: Nonce) -> Cipher {
        Cipher::new(b"secret", nonce).expect("собирается")
    }

    #[test]
    fn an_odd_second_is_rounded_up_to_even() {
        assert_eq!(tcp_timestamp(1), 2);
        assert_eq!(tcp_timestamp(2), 2);
        assert_eq!(tcp_timestamp(3), 4);
    }

    #[test]
    fn the_first_fragment_carries_the_timestamp_before_the_address() {
        let target = SocketAddress::ip(Ipv4Addr::new(203, 0, 113, 5).into(), 443);
        let fragment = first_fragment(100, &target).expect("собирается");

        assert_eq!(
            &fragment[..4],
            &100u32.to_be_bytes(),
            "метка стоит не первой"
        );
        let (decoded, consumed) = socks::decode(&fragment[4..])
            .expect("разбирается")
            .expect("целиком");
        assert_eq!(decoded, target);
        assert_eq!(consumed, fragment.len() - 4);
    }

    #[test]
    fn what_is_sealed_round_trips_through_open() {
        let mut send = cipher([1u8; 12]);
        let mut recv = cipher([1u8; 12]);

        let mut wire = seal_fragment(&mut send, b"hello").expect("шифруется");
        let length_frame: Vec<u8> = wire.drain(..LENGTH_FRAME).collect();

        let mut length_frame = length_frame;
        let length = open_length(&mut recv, &mut length_frame).expect("длина читается");
        assert_eq!(usize::from(length), b"hello".len());

        let plain_len = recv.open(&mut wire).expect("данные читаются");
        assert_eq!(&wire[..plain_len], b"hello");
    }

    #[test]
    fn a_payload_over_the_server_buffer_is_refused() {
        // Настоящий сервер такой кусок никогда не читал бы целиком — его
        // буфер на TCP-направление ровно 2048 байт.
        let mut send = cipher([2u8; 12]);
        let oversized = vec![0u8; MAX_PAYLOAD + 1];
        assert!(matches!(
            seal_fragment(&mut send, &oversized),
            Err(BrookError::Oversized(_))
        ));
    }

    #[test]
    fn a_payload_at_the_limit_is_accepted() {
        let mut send = cipher([3u8; 12]);
        let exact = vec![7u8; MAX_PAYLOAD];
        assert!(seal_fragment(&mut send, &exact).is_ok());
    }

    #[test]
    fn the_max_payload_matches_the_reference_buffer_arithmetic() {
        // `len(dst) > 2048-2-16-4-16` в `NewStreamClient` — тот же буфер,
        // просто для первого кадра, где ещё есть четыре байта метки времени.
        assert_eq!(MAX_PAYLOAD, 2048 - 2 - 16 - 16);
    }
}
