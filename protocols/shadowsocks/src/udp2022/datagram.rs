//! Канал датаграмм UDP 2022: свой идентификатор сессии, растущий счётчик
//! пакета вместо соли на каждой посылке.
//!
//! ```text
//!  AES-GCM: [заголовок(16, шифр AES-ECB на PSK)] [AEAD(тело) + метка]
//!  ChaCha:  [нонс(24, случайный)] [AEAD(идентификатор сессии || счётчик || тело) + метка]
//! ```
//!
//! Окна антиреплея и кеша смены сессии (`sing-shadowsocks2`: `udpSession.window`) нет:
//! это защита сервера. Клиент проверяет только, что ответ несёт наш идентификатор сессии.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_proto::random;
use tokio::net::UdpSocket;

use crate::error::{ShadowsocksError, ShadowsocksResult};
use crate::header2022;
use crate::kdf2022;
use crate::method::Method2022;
use crate::udp2022::cipher::{self, CHACHA_NONCE_LEN, HEADER_LEN, TAG_LEN};
use crate::udp2022::header;

/// Наибольшая датаграмма, которую вообще можно получить.
const MAX_DATAGRAM: usize = 65_535;

/// Канал датаграмм через сервер Shadowsocks 2022.
pub struct ShadowsocksDatagram2022 {
    socket: UdpSocket,
    server: SocketAddr,
    method: Method2022,
    psk: Vec<u8>,
    session_id: u64,
    packet_id: AtomicU64,
}

impl std::fmt::Debug for ShadowsocksDatagram2022 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksDatagram2022")
            .field("server", &self.server)
            .field("method", &self.method.name())
            .finish()
    }
}

impl ShadowsocksDatagram2022 {
    /// Собирает канал вокруг открытого сокета; идентификатор сессии случайный, на весь срок жизни.
    pub fn new(socket: UdpSocket, server: SocketAddr, method: Method2022, psk: Vec<u8>) -> Self {
        Self {
            socket,
            server,
            method,
            psk,
            session_id: u64::from_be_bytes(random::array()),
            packet_id: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl ProxyDatagram for ShadowsocksDatagram2022 {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed);
        let body = header::build_client_body(header2022::now_unix(), target, &payload)?;
        let wire = seal(self.method, &self.psk, self.session_id, packet_id, &body)?;
        self.socket.send_to(&wire, self.server).await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut buffer = vec![0u8; MAX_DATAGRAM];
        loop {
            let (len, from) = self.socket.recv_from(&mut buffer).await?;
            if from.ip() != self.server.ip() {
                tracing::debug!(%from, "датаграмма 2022 не от сервера — отброшена");
                continue;
            }

            match open(self.method, &self.psk, self.session_id, &mut buffer[..len]) {
                Ok(found) => return Ok(found),
                Err(err) => {
                    tracing::debug!(%from, %err, "датаграмма 2022 не разобралась — отброшена");
                }
            }
        }
    }
}

/// Собирает датаграмму: заголовок сессии, потом тело под AEAD.
fn seal(
    method: Method2022,
    psk: &[u8],
    session_id: u64,
    packet_id: u64,
    body: &[u8],
) -> ShadowsocksResult<Vec<u8>> {
    if method.is_aes_gcm() {
        let mut header16 = [0u8; HEADER_LEN];
        header16[..8].copy_from_slice(&session_id.to_be_bytes());
        header16[8..].copy_from_slice(&packet_id.to_be_bytes());

        let key = kdf2022::derive(psk, &header16[..8], method.key_len());
        let mut nonce12 = [0u8; 12];
        nonce12.copy_from_slice(&header16[4..]);

        let mut wire = Vec::with_capacity(HEADER_LEN + body.len() + TAG_LEN);
        wire.extend_from_slice(&header16);
        wire.extend_from_slice(body);
        let tag = cipher::aesgcm_seal(method, &key, &nonce12, &mut wire[HEADER_LEN..])?;
        wire.extend_from_slice(&tag);

        cipher::ecb_encrypt_header(method, psk, &mut header16)?;
        wire[..HEADER_LEN].copy_from_slice(&header16);
        Ok(wire)
    } else {
        let nonce24 = random::array::<CHACHA_NONCE_LEN>();

        let mut wire = Vec::with_capacity(CHACHA_NONCE_LEN + 16 + body.len() + TAG_LEN);
        wire.extend_from_slice(&nonce24);
        wire.extend_from_slice(&session_id.to_be_bytes());
        wire.extend_from_slice(&packet_id.to_be_bytes());
        wire.extend_from_slice(body);
        let tag = cipher::xchacha_seal(psk, &nonce24, &mut wire[CHACHA_NONCE_LEN..])?;
        wire.extend_from_slice(&tag);
        Ok(wire)
    }
}

/// Разбирает пришедшую датаграмму.
fn open(
    method: Method2022,
    psk: &[u8],
    our_session_id: u64,
    datagram: &mut [u8],
) -> ShadowsocksResult<(Bytes, SocketAddress)> {
    let plain: &[u8] = if method.is_aes_gcm() {
        let Some((header_bytes, body)) = datagram.split_first_chunk_mut::<HEADER_LEN>() else {
            return Err(ShadowsocksError::malformed(
                "датаграмма 2022 короче заголовка",
            ));
        };
        cipher::ecb_decrypt_header(method, psk, header_bytes)?;

        let key = kdf2022::derive(psk, &header_bytes[..8], method.key_len());
        let plain_len = cipher::aesgcm_open(method, &key, &header_bytes[4..], body)?;
        &body[..plain_len]
    } else {
        let Some((nonce24, sealed)) = datagram.split_first_chunk_mut::<CHACHA_NONCE_LEN>() else {
            return Err(ShadowsocksError::malformed("датаграмма 2022 короче нонса"));
        };
        let opened_len = cipher::xchacha_open(psk, nonce24, sealed)?;
        let Some(body) = sealed[..opened_len].get(16..) else {
            return Err(ShadowsocksError::malformed(
                "датаграмма 2022 короче идентификатора сессии и счётчика",
            ));
        };
        body
    };

    let (client_session_id, source, payload) =
        header::parse_server_body(plain, header2022::now_unix())?;
    if client_session_id != our_session_id {
        return Err(ShadowsocksError::malformed(
            "датаграмма 2022: сервер подтвердил не наш идентификатор сессии",
        ));
    }
    Ok((Bytes::copy_from_slice(payload), source))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK_AES: [u8; 16] = [7u8; 16];
    const PSK_CHACHA: [u8; 32] = [7u8; 32];

    fn target() -> SocketAddress {
        SocketAddress::domain("dns.example.com", 53)
    }

    /// Собирает то, что прислал бы сервер, — руками, теми же примитивами,
    /// какими сервер и должен собирать ответ.
    fn from_server(
        method: Method2022,
        psk: &[u8],
        client_session_id: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let server_session_id = 999u64;
        let mut body = vec![header2022::TYPE_SERVER];
        body.extend_from_slice(&header2022::now_unix().to_be_bytes());
        body.extend_from_slice(&client_session_id.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        penguin_transport::addr::socks::encode(&target(), &mut body).unwrap();
        body.extend_from_slice(payload);

        seal(method, psk, server_session_id, 0, &body).expect("собирается")
    }

    #[test]
    fn a_datagram_survives_the_round_trip_aes_gcm() {
        let session_id = 42u64;
        let mut wire = from_server(Method2022::Blake3Aes128Gcm, &PSK_AES, session_id, b"answer");
        let (payload, source) = open(Method2022::Blake3Aes128Gcm, &PSK_AES, session_id, &mut wire)
            .expect("разбирается");
        assert_eq!(&payload[..], b"answer");
        assert_eq!(source, target());
    }

    #[test]
    fn a_datagram_survives_the_round_trip_chacha() {
        let session_id = 42u64;
        let mut wire = from_server(
            Method2022::Blake3Chacha20Poly1305,
            &PSK_CHACHA,
            session_id,
            b"answer",
        );
        let (payload, source) = open(
            Method2022::Blake3Chacha20Poly1305,
            &PSK_CHACHA,
            session_id,
            &mut wire,
        )
        .expect("разбирается");
        assert_eq!(&payload[..], b"answer");
        assert_eq!(source, target());
    }

    #[test]
    fn a_response_to_someone_elses_session_is_rejected() {
        let mut wire = from_server(Method2022::Blake3Aes128Gcm, &PSK_AES, 1, b"answer");
        assert!(open(Method2022::Blake3Aes128Gcm, &PSK_AES, 2, &mut wire).is_err());
    }

    #[test]
    fn every_send_uses_a_fresh_packet_id_and_the_wire_differs() {
        let body = header::build_client_body(1_000, &target(), b"same").expect("собирается");
        let first = seal(Method2022::Blake3Aes128Gcm, &PSK_AES, 1, 0, &body).expect("собирается");
        let second = seal(Method2022::Blake3Aes128Gcm, &PSK_AES, 1, 1, &body).expect("собирается");
        assert_ne!(first, second);
    }

    #[test]
    fn a_datagram_from_a_different_key_does_not_open() {
        let mut wire = from_server(Method2022::Blake3Aes128Gcm, &PSK_AES, 1, b"answer");
        assert!(open(Method2022::Blake3Aes128Gcm, &[9u8; 16], 1, &mut wire).is_err());
    }
}
