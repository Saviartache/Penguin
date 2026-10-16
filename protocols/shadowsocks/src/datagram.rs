//! Датаграммы: своя соль и свой ключ на каждую посылку (UDP без порядка и доставки).
//!
//! ```text
//!  [соль] [ шифр( адрес || данные ) + метка ]
//! ```
//!
//! Чужие и нерасшифровавшиеся датаграммы отбрасываются молча.

use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_proto::random;
use penguin_transport::addr::socks;
use tokio::net::UdpSocket;

use crate::crypto::sealed_len;
use crate::crypto::{Cipher, Method, kdf};
use crate::error::{ShadowsocksError, ShadowsocksResult};

/// Наибольшая датаграмма, которую вообще можно получить.
const MAX_DATAGRAM: usize = 65_535;

/// Канал датаграмм через сервер Shadowsocks.
pub struct ShadowsocksDatagram {
    socket: UdpSocket,
    server: SocketAddr,
    method: Method,
    master: Vec<u8>,
}

impl std::fmt::Debug for ShadowsocksDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksDatagram")
            .field("server", &self.server)
            .field("method", &self.method.name())
            .finish()
    }
}

impl ShadowsocksDatagram {
    /// Собирает канал вокруг уже открытого сокета.
    pub fn new(socket: UdpSocket, server: SocketAddr, method: Method, master: Vec<u8>) -> Self {
        Self {
            socket,
            server,
            method,
            master,
        }
    }
}

#[async_trait]
impl ProxyDatagram for ShadowsocksDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let frame = seal(self.method, &self.master, target, &payload)?;
        self.socket.send_to(&frame, self.server).await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut buffer = vec![0u8; MAX_DATAGRAM];
        loop {
            let (len, from) = self.socket.recv_from(&mut buffer).await?;
            if from.ip() != self.server.ip() {
                tracing::debug!(%from, "датаграмма не от сервера — отброшена");
                continue;
            }

            match open(self.method, &self.master, &mut buffer[..len]) {
                Ok(found) => return Ok(found),
                Err(err) => {
                    tracing::debug!(%from, %err, "датаграмма не разобралась — отброшена");
                }
            }
        }
    }
}

/// Собирает датаграмму: соль, потом шифр от адреса и данных.
pub fn seal(
    method: Method,
    master: &[u8],
    target: &SocketAddress,
    payload: &[u8],
) -> ShadowsocksResult<Vec<u8>> {
    let mut salt = vec![0u8; method.salt_len()];
    random::fill(&mut salt);

    let key = kdf::session_key(master, &salt, method)?;
    let mut cipher = Cipher::new(method.algorithm(), &key)?;

    let from = salt.len();
    salt.reserve(sealed_len(socks::encoded_len(target) + payload.len()));
    socks::encode(target, &mut salt)?;
    salt.extend_from_slice(payload);

    cipher.seal_in_place(&mut salt, from)?;
    Ok(salt)
}

/// Разбирает пришедшую датаграмму.
pub fn open(
    method: Method,
    master: &[u8],
    datagram: &mut [u8],
) -> ShadowsocksResult<(Bytes, SocketAddress)> {
    let salt_len = method.salt_len();
    if datagram.len() < salt_len + sealed_len(0) {
        return Err(ShadowsocksError::malformed("датаграмма короче заголовка"));
    }

    let (salt, body) = datagram.split_at_mut(salt_len);
    let key = kdf::session_key(master, salt, method)?;
    let mut cipher = Cipher::new(method.algorithm(), &key)?;
    let plain = cipher.open(body)?;

    let Some((source, used)) = socks::decode(&body[..plain])? else {
        return Err(ShadowsocksError::malformed("адрес в датаграмме оборван"));
    };
    Ok((Bytes::copy_from_slice(&body[used..plain]), source))
}

#[cfg(test)]
mod tests {
    use super::*;

    const METHOD: Method = Method::Aes256Gcm;

    fn master() -> Vec<u8> {
        kdf::master_key("пароль от сервера", METHOD)
    }

    fn target() -> SocketAddress {
        SocketAddress::domain("dns.example.com", 53)
    }

    #[test]
    fn a_datagram_survives_the_round_trip() {
        let master = master();
        let mut wire = seal(METHOD, &master, &target(), b"\x00\x01query").expect("собирается");

        let (payload, source) = open(METHOD, &master, &mut wire).expect("разбирается");
        assert_eq!(&payload[..], b"\x00\x01query");
        assert_eq!(source, target());
    }

    #[test]
    fn every_datagram_carries_its_own_salt() {
        // Иначе потерянный пакет сдвинул бы счётчик, и всё остальное перестало
        // бы расшифровываться.
        let master = master();
        let first = seal(METHOD, &master, &target(), b"same").expect("собирается");
        let second = seal(METHOD, &master, &target(), b"same").expect("собирается");

        assert_ne!(first[..METHOD.salt_len()], second[..METHOD.salt_len()]);
        assert_ne!(first, second);
    }

    #[test]
    fn an_empty_payload_is_still_a_datagram() {
        let master = master();
        let mut wire = seal(METHOD, &master, &target(), b"").expect("собирается");
        let (payload, _) = open(METHOD, &master, &mut wire).expect("разбирается");
        assert!(payload.is_empty());
    }

    #[test]
    fn a_datagram_from_someone_else_does_not_open() {
        let mut wire = seal(METHOD, &master(), &target(), b"query").expect("собирается");
        let other = kdf::master_key("другой пароль", METHOD);
        assert!(open(METHOD, &other, &mut wire).is_err());
    }

    #[test]
    fn a_changed_byte_is_noticed() {
        let master = master();
        let mut wire = seal(METHOD, &master, &target(), b"query").expect("собирается");
        let last = wire.len() - 1;
        wire[last] ^= 1;
        assert!(open(METHOD, &master, &mut wire).is_err());
    }

    #[test]
    fn a_short_datagram_is_refused_before_the_key_is_derived() {
        // Вывод ключа на каждый мусорный пакет — это работа впустую ровно с
        // той скоростью, с какой его шлют.
        let master = master();
        for len in 0..METHOD.salt_len() + 16 {
            let mut wire = vec![0u8; len];
            assert!(open(METHOD, &master, &mut wire).is_err(), "длина {len}");
        }
    }

    #[test]
    fn every_method_round_trips() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let master = kdf::master_key("пароль", method);
            let mut wire = seal(method, &master, &target(), b"query").expect("собирается");
            let (payload, source) = open(method, &master, &mut wire).expect("разбирается");
            assert_eq!(&payload[..], b"query", "{}", method.name());
            assert_eq!(source, target());
        }
    }
}
