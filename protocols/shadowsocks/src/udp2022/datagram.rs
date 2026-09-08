//! Канал датаграмм UDP 2022: свой идентификатор сессии, растущий счётчик
//! пакета вместо соли на каждой посылке.
//!
//! ```text
//!  AES-GCM: [заголовок(16, шифр AES-ECB на PSK)] [AEAD(тело) + метка]
//!  ChaCha:  [нонс(24, случайный)] [AEAD(идентификатор сессии || счётчик || тело) + метка]
//! ```
//!
//! # Почему не соль на каждой, как у обычного AEAD
//!
//! У 2022 своя схема защиты от повтора: один идентификатор сессии на весь
//! срок жизни сокета и счётчик пакета, растущий на каждой посылке. Отдельная
//! соль здесь была бы лишней платой — тело и так не расшифровать без верного
//! идентификатора сессии.
//!
//! # Что упрощено против эталона
//!
//! `shadowsocks-rust` и `sing-shadowsocks2` держат на сервере окно
//! антиреплея и кеш смены сессии собеседника (`sing-shadowsocks2`:
//! `udpSession.window`, `lastRemoteSessionId`). Это защита сервера от
//! злонамеренного клиента; клиенту, которому нужно принять свой же трафик от
//! одного сервера, она без надобности. Здесь подключ пересчитывается заново
//! на каждый пришедший пакет по идентификатору сессии из самого пакета, и
//! единственная проверка — что сервер вернул **наш** идентификатор сессии
//! (иначе ответ не на наш запрос).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use rand::Rng;
use tokio::net::UdpSocket;

use crate::error::{ShadowsocksError, ShadowsocksResult};
use crate::header2022;
use crate::kdf2022;
use crate::method::Method2022;
use crate::udp2022::cipher::{self, CHACHA_NONCE_LEN, HEADER_LEN};
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
    /// Собирает канал вокруг уже открытого сокета. Идентификатор сессии —
    /// свой на весь срок жизни сокета, случайный.
    pub fn new(socket: UdpSocket, server: SocketAddr, method: Method2022, psk: Vec<u8>) -> Self {
        let mut session_id = [0u8; 8];
        rand::thread_rng().fill(&mut session_id[..]);

        Self {
            socket,
            server,
            method,
            psk,
            session_id: u64::from_be_bytes(session_id),
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
        loop {
            let mut buffer = vec![0u8; MAX_DATAGRAM];
            let (len, from) = self.socket.recv_from(&mut buffer).await?;

            if from.ip() != self.server.ip() {
                tracing::debug!(%from, "датаграмма 2022 не от сервера — отброшена");
                continue;
            }

            buffer.truncate(len);
            match open(self.method, &self.psk, self.session_id, &buffer) {
                Ok(found) => return Ok(found),
                Err(err) => {
                    tracing::debug!(%from, %err, "датаграмма 2022 не разобралась — отброшена");
                    continue;
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
        let nonce12 = header16[4..16].to_vec();

        let mut wire_body = body.to_vec();
        cipher::aesgcm_seal(method, &key, &nonce12, &mut wire_body)?;

        cipher::ecb_encrypt_header(method, psk, &mut header16)?;

        let mut wire = header16.to_vec();
        wire.extend_from_slice(&wire_body);
        Ok(wire)
    } else {
        let mut nonce24 = [0u8; CHACHA_NONCE_LEN];
        rand::thread_rng().fill(&mut nonce24[..]);

        let mut plain = Vec::with_capacity(16 + body.len());
        plain.extend_from_slice(&session_id.to_be_bytes());
        plain.extend_from_slice(&packet_id.to_be_bytes());
        plain.extend_from_slice(body);

        let sealed = cipher::xchacha_seal(psk, &nonce24, &plain)?;

        let mut wire = nonce24.to_vec();
        wire.extend_from_slice(&sealed);
        Ok(wire)
    }
}

/// Разбирает пришедшую датаграмму.
fn open(
    method: Method2022,
    psk: &[u8],
    our_session_id: u64,
    datagram: &[u8],
) -> ShadowsocksResult<(Bytes, SocketAddress)> {
    let plain = if method.is_aes_gcm() {
        if datagram.len() < HEADER_LEN {
            return Err(ShadowsocksError::malformed(
                "датаграмма 2022 короче заголовка",
            ));
        }
        let (header_bytes, body) = datagram.split_at(HEADER_LEN);

        let mut header16 = [0u8; HEADER_LEN];
        header16.copy_from_slice(header_bytes);
        cipher::ecb_decrypt_header(method, psk, &mut header16)?;

        let key = kdf2022::derive(psk, &header16[..8], method.key_len());
        let nonce12 = header16[4..16].to_vec();

        let mut body = body.to_vec();
        let plain_len = cipher::aesgcm_open(method, &key, &nonce12, &mut body)?;
        body.truncate(plain_len);
        body
    } else {
        if datagram.len() < CHACHA_NONCE_LEN {
            return Err(ShadowsocksError::malformed("датаграмма 2022 короче нонса"));
        }
        let (nonce, ciphertext) = datagram.split_at(CHACHA_NONCE_LEN);
        let nonce24: [u8; CHACHA_NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| ShadowsocksError::malformed("нонс 2022 не той длины"))?;

        let mut opened = cipher::xchacha_open(psk, &nonce24, ciphertext)?;
        if opened.len() < 16 {
            return Err(ShadowsocksError::malformed(
                "датаграмма 2022 короче идентификатора сессии и счётчика",
            ));
        }
        opened.split_off(16)
    };

    let (client_session_id, source, payload) =
        header::parse_server_body(&plain, header2022::now_unix())?;
    if client_session_id != our_session_id {
        return Err(ShadowsocksError::malformed(
            "датаграмма 2022: сервер подтвердил не наш идентификатор сессии",
        ));
    }
    Ok((Bytes::from(payload), source))
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
        let wire = from_server(Method2022::Blake3Aes128Gcm, &PSK_AES, session_id, b"answer");
        let (payload, source) =
            open(Method2022::Blake3Aes128Gcm, &PSK_AES, session_id, &wire).expect("разбирается");
        assert_eq!(&payload[..], b"answer");
        assert_eq!(source, target());
    }

    #[test]
    fn a_datagram_survives_the_round_trip_chacha() {
        let session_id = 42u64;
        let wire = from_server(
            Method2022::Blake3Chacha20Poly1305,
            &PSK_CHACHA,
            session_id,
            b"answer",
        );
        let (payload, source) = open(
            Method2022::Blake3Chacha20Poly1305,
            &PSK_CHACHA,
            session_id,
            &wire,
        )
        .expect("разбирается");
        assert_eq!(&payload[..], b"answer");
        assert_eq!(source, target());
    }

    #[test]
    fn a_response_to_someone_elses_session_is_rejected() {
        let wire = from_server(Method2022::Blake3Aes128Gcm, &PSK_AES, 1, b"answer");
        assert!(open(Method2022::Blake3Aes128Gcm, &PSK_AES, 2, &wire).is_err());
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
        let wire = from_server(Method2022::Blake3Aes128Gcm, &PSK_AES, 1, b"answer");
        assert!(open(Method2022::Blake3Aes128Gcm, &[9u8; 16], 1, &wire).is_err());
    }
}
