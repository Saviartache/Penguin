//! Датаграммный канал внутри сессии.
//!
//! Один канал обслуживает всю UDP-сессию приложения: адрес назначения едет на
//! каждой посылке, отдельного канала на каждого собеседника не заводится.
//!
//! # Почему датаграмму законно потерять
//!
//! Потому что это UDP. Очередь канала не ждёт места, а выбрасывает лишнее:
//! приложение, пославшее тысячу запросов и не читающее ответы, не имеет права
//! остановить чужие потоки в той же сессии. У потоков всё наоборот — там
//! ждут, и там же объяснено, почему (см. [`crate::mux::session`]).

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_transport::addr::socks;
use tokio::sync::{Mutex, mpsc};

use crate::error::PingwinError;
use crate::mux::session::Session;
use crate::wire::frame;

/// Датаграммный канал Pingwin.
pub struct PingwinDatagram {
    session: Arc<Session>,
    id: u32,
    /// Что пришло из сессии. Под замком: трейт отдаёт `&self`.
    incoming: Mutex<mpsc::Receiver<(Bytes, SocketAddress)>>,
}

impl std::fmt::Debug for PingwinDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingwinDatagram")
            .field("id", &self.id)
            .finish()
    }
}

impl PingwinDatagram {
    /// Собирает канал. Зовут его только [`Session`] и её просьбы.
    pub(crate) fn new(
        session: Arc<Session>,
        id: u32,
        incoming: mpsc::Receiver<(Bytes, SocketAddress)>,
    ) -> Self {
        Self {
            session,
            id,
            incoming: Mutex::new(incoming),
        }
    }

    /// Номер канала в сессии.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Собирает тело кадра: адрес и за ним датаграмма.
    fn body(payload: &[u8], target: &SocketAddress) -> Result<Vec<u8>, PingwinError> {
        let mut body = Vec::with_capacity(socks::encoded_len(target) + payload.len());
        socks::encode(target, &mut body)?;
        body.extend_from_slice(payload);
        if body.len() > frame::MAX_PAYLOAD {
            return Err(PingwinError::Oversized(body.len()));
        }
        Ok(body)
    }
}

#[async_trait]
impl ProxyDatagram for PingwinDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let body = Self::body(&payload, target)?;
        Ok(self.session.send(frame::UDP, self.id, &body).await?)
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut incoming = self.incoming.lock().await;
        incoming.recv().await.ok_or_else(|| {
            ProtocolError::from(PingwinError::disconnected("датаграммный канал закрылся"))
        })
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.session.forget(self.id);
        if self.session.is_dead() {
            return Ok(());
        }
        Ok(self
            .session
            .send(frame::RST, self.id, "канал закрыт".as_bytes())
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_goes_in_front_of_the_datagram() {
        // Собеседник читает адрес первым: перепутать порядок — значит
        // отправить чужой запрос по адресу из его же тела.
        let target = SocketAddress::domain("example.com", 53);
        let body = PingwinDatagram::body(b"query", &target).expect("собирается");

        let (parsed, used) = socks::decode(&body)
            .expect("разбирается")
            .expect("адрес целиком");
        assert_eq!(parsed, target);
        assert_eq!(&body[used..], b"query");
    }

    #[test]
    fn a_datagram_that_does_not_fit_a_frame_is_refused() {
        // Резать датаграмму нельзя: границы посылки — это и есть UDP.
        let target = SocketAddress::domain("example.com", 53);
        let huge = vec![0u8; frame::MAX_PAYLOAD];
        assert!(PingwinDatagram::body(&huge, &target).is_err());
    }
}
