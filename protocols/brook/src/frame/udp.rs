//! Кадр UDP: вся датаграмма — один кусок, своя соль на каждой посылке.
//!
//! ```text
//!  ──► [нонс 12, открытым текстом] [шифр(метка времени + адрес + данные) + метка]
//! ```
//!
//! У UDP нет ни порядка, ни доставки, и держать один нонс на весь канал, как
//! это устроено у TCP ([`crate::frame::tcp`]), означало бы, что потерянная
//! датаграмма сдвигает счётчик и рвёт всё, что придёт следом. Поэтому здесь
//! нонс не переиспользуется и не двигается: он бросается заново на каждую
//! посылку и участвует только один раз — сразу и как соль для ключа, и как
//! значение счётчика AES-GCM.
//!
//! Метка времени есть только в сторону сервера — эталон (`packetclient.go`) не
//! проверяет её на входящих датаграммах, читать её оттуда некому. Ответ несёт
//! просто `DST Address + Data`, где адрес — это то, откуда сервер получил
//! данные, а не то, куда клиент их посылал.
//!
//! Ограничение на размер — [`MAX_DATAGRAM`], предел, каким его считает эталон
//! (`x.BP65507`): наибольший пакет UDP по IPv4 без джамбограмм.

use penguin_core::address::SocketAddress;
use penguin_transport::addr::socks;
use rand::Rng;

use crate::error::{BrookError, BrookResult};
use crate::frame::cipher::Cipher;
use crate::frame::nonce::{NONCE_LEN, Nonce};

/// Наибольшая датаграмма целиком, вместе с нонсом и меткой.
pub const MAX_DATAGRAM: usize = 65_507;

/// Собирает исходящую датаграмму: свежий нонс, метка времени, адрес, данные.
pub fn seal_client_datagram(
    password: &[u8],
    now_unix: u64,
    target: &SocketAddress,
    payload: &[u8],
) -> BrookResult<Vec<u8>> {
    let nonce: Nonce = random_nonce();

    let mut plain = Vec::with_capacity(4 + socks::encoded_len(target) + payload.len());
    plain.extend_from_slice(&(now_unix as u32).to_be_bytes());
    socks::encode(target, &mut plain).map_err(BrookError::from)?;
    plain.extend_from_slice(payload);

    if NONCE_LEN + plain.len() + crate::frame::cipher::TAG_LEN > MAX_DATAGRAM {
        return Err(BrookError::Oversized(payload.len()));
    }

    let mut cipher = Cipher::new(password, nonce)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&cipher.seal(&plain)?);
    Ok(out)
}

/// Разбирает входящую датаграмму сервера: адрес отправителя и данные.
///
/// `datagram` изменяется на месте — расшифровка AES-GCM всегда так делает.
pub fn open_server_datagram(
    password: &[u8],
    datagram: &mut [u8],
) -> BrookResult<(SocketAddress, std::ops::Range<usize>)> {
    if datagram.len() < NONCE_LEN {
        return Err(BrookError::malformed("датаграмма короче нонса"));
    }
    let (nonce_bytes, body) = datagram.split_at_mut(NONCE_LEN);
    let nonce: Nonce = nonce_bytes
        .first_chunk::<NONCE_LEN>()
        .copied()
        .ok_or_else(|| BrookError::malformed("нонс не той длины"))?;

    let mut cipher = Cipher::new(password, nonce)?;
    let plain_len = cipher.open(body)?;

    let (address, consumed) = socks::decode(&body[..plain_len])
        .map_err(BrookError::from)?
        .ok_or_else(|| BrookError::malformed("адрес в ответе не поместился целиком"))?;

    // Диапазон — в системе координат исходного среза: `body` начинается
    // сразу после нонса, то есть со сдвигом в `NONCE_LEN`.
    let start = NONCE_LEN + consumed;
    let end = NONCE_LEN + plain_len;
    Ok((address, start..end))
}

/// Свежий нонс на одну датаграмму.
fn random_nonce() -> Nonce {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn target() -> SocketAddress {
        SocketAddress::ip(Ipv4Addr::new(198, 51, 100, 7).into(), 53)
    }

    #[test]
    fn what_the_client_seals_the_server_shape_can_be_read_back() {
        // Проверяем не через `open_server_datagram` (у него нет метки
        // времени в открытом тексте), а напрямую: расшифровываем и разбираем
        // руками, чтобы убедиться, что порядок полей ровно такой, как в
        // документе протокола.
        let sealed = seal_client_datagram(b"secret", 42, &target(), b"query").expect("шифруется");
        assert!(sealed.len() > NONCE_LEN, "нонс не уместился");

        let nonce: Nonce = sealed[..NONCE_LEN].try_into().expect("двенадцать байт");
        let mut body = sealed[NONCE_LEN..].to_vec();
        let mut cipher = Cipher::new(b"secret", nonce).expect("собирается");
        let len = cipher.open(&mut body).expect("расшифровывается");

        assert_eq!(
            &body[..4],
            &42u32.to_be_bytes(),
            "метка времени стоит не первой"
        );
        let (address, consumed) = socks::decode(&body[4..len]).unwrap().unwrap();
        assert_eq!(address, target());
        assert_eq!(&body[4 + consumed..len], b"query");
    }

    #[test]
    fn two_datagrams_never_share_a_nonce() {
        // Общий нонс на две датаграммы под одним ключом — это раскрытые
        // данные для AEAD, а не просто более слабая защита.
        let first = seal_client_datagram(b"secret", 1, &target(), b"a").expect("шифруется");
        let second = seal_client_datagram(b"secret", 1, &target(), b"a").expect("шифруется");
        assert_ne!(&first[..NONCE_LEN], &second[..NONCE_LEN]);
    }

    #[test]
    fn a_server_reply_has_no_timestamp_and_carries_the_source_address() {
        // Ответ сервера в реальности не несёт метку времени — этот тест
        // собирает его руками, как это делал бы сервер, и проверяет, что наш
        // разбор ждёт именно такую форму, а не форму запроса.
        let nonce: Nonce = [9u8; NONCE_LEN];
        let mut plain = Vec::new();
        socks::encode(&target(), &mut plain).unwrap();
        plain.extend_from_slice(b"answer");

        let mut cipher = Cipher::new(b"secret", nonce).expect("собирается");
        let mut datagram = nonce.to_vec();
        datagram.extend_from_slice(&cipher.seal(&plain).expect("шифруется"));

        let (address, range) = open_server_datagram(b"secret", &mut datagram).expect("разбирается");
        assert_eq!(address, target());
        assert_eq!(&datagram[range], b"answer");
    }

    #[test]
    fn a_wrong_password_is_rejected_not_panicked() {
        let mut datagram = seal_client_datagram(b"secret", 1, &target(), b"x").expect("шифруется");
        assert!(open_server_datagram("не тот пароль".as_bytes(), &mut datagram).is_err());
    }

    #[test]
    fn a_datagram_shorter_than_the_nonce_is_an_error_not_a_panic() {
        let mut short = vec![0u8; NONCE_LEN - 1];
        assert!(open_server_datagram(b"secret", &mut short).is_err());
    }
}
