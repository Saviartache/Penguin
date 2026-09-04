//! Канал датаграмм поверх сеанса.
//!
//! Проще, чем у VLESS, и по хорошей причине: адрес назначения стоит на каждой
//! посылке, значит одного канала хватает на всех адресатов. Дополнительных
//! потоков не нужно вовсе — всё едет по уже установленному соединению QUIC.
//!
//! # Номер датаграммы
//!
//! Он свой у каждой посылки и нужен на приёме: по нему собираются части. Ходит
//! по кругу — шестнадцать бит, — и это не проблема ровно потому, что
//! недособранное живёт секунды, а не минуты.

use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use tokio::sync::{Mutex, mpsc};

use crate::error::TuicError;
use crate::session::Session;

/// Канал датаграмм через сервер TUIC.
pub struct TuicDatagram {
    session: Arc<Session>,
    /// Номер канала. Сервер держит за ним своё состояние.
    association: u16,
    /// Номер следующей датаграммы.
    packet: AtomicU16,
    incoming: Mutex<mpsc::Receiver<(Bytes, SocketAddress)>>,
}

impl std::fmt::Debug for TuicDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicDatagram")
            .field("association", &self.association)
            .finish()
    }
}

impl TuicDatagram {
    /// Заводит канал внутри сеанса.
    pub fn new(session: Arc<Session>) -> Self {
        let (association, incoming) = session.open_association();
        Self {
            session,
            association,
            packet: AtomicU16::new(0),
            incoming: Mutex::new(incoming),
        }
    }
}

#[async_trait]
impl ProxyDatagram for TuicDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let packet = self.packet.fetch_add(1, Ordering::Relaxed);
        self.session
            .send_packet(self.association, packet, target, &payload)
            .await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut incoming = self.incoming.lock().await;
        incoming.recv().await.ok_or_else(|| {
            // Отправитель живёт в сеансе: пустая очередь означает, что сеанс
            // закрыт или канал сняли.
            TuicError::Disconnected("канал датаграмм закрыт".to_owned()).into()
        })
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.session.close_association(self.association).await;
        Ok(())
    }
}
