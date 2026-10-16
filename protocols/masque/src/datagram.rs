//! [`ProxyDatagram`] поверх `CONNECT-UDP`: канал с произвольным адресом на
//! каждой посылке, собранный из каналов `CONNECT-UDP` с ровно одним адресом
//! каждый.
//!
//! RFC 9298 привязывает поток к одному адресу (§2), а `send_to` получает адрес
//! с каждым пакетом, поэтому [`MasqueDatagram`] держит [`Flow`] на каждый
//! адрес поверх одного соединения [`Session`].

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use tokio::sync::{Mutex, mpsc};

use crate::error::MasqueError;
use crate::flow::Flow;
use crate::session::Session;

/// Сколько датаграмм ждёт `recv_from`.
const INCOMING_CAPACITY: usize = 256;

/// Канал датаграмм через прокси MASQUE.
pub struct MasqueDatagram {
    session: Arc<Session>,
    flows: Mutex<HashMap<SocketAddress, Arc<Flow>>>,
    incoming_tx: mpsc::Sender<(Bytes, SocketAddress)>,
    incoming_rx: Mutex<mpsc::Receiver<(Bytes, SocketAddress)>>,
}

impl std::fmt::Debug for MasqueDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueDatagram").finish()
    }
}

impl MasqueDatagram {
    /// Заводит канал поверх уже установленного соединения с прокси.
    pub fn new(session: Arc<Session>) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_CAPACITY);
        Self {
            session,
            flows: Mutex::new(HashMap::new()),
            incoming_tx,
            incoming_rx: Mutex::new(incoming_rx),
        }
    }

    /// Отдаёт канал до `target`: уже открытый или только что открытый.
    async fn flow_for(&self, target: &SocketAddress) -> Result<Arc<Flow>, MasqueError> {
        let mut flows = self.flows.lock().await;
        if let Some(flow) = flows.get(target) {
            return Ok(Arc::clone(flow));
        }

        let flow = Arc::new(
            self.session
                .open_flow(target, self.incoming_tx.clone())
                .await?,
        );
        flows.insert(target.clone(), Arc::clone(&flow));
        Ok(flow)
    }

    /// Убирает мёртвый канал из кэша.
    async fn evict(&self, target: &SocketAddress) {
        self.flows.lock().await.remove(target);
    }
}

#[async_trait]
impl ProxyDatagram for MasqueDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let flow = self.flow_for(target).await?;
        if let Err(err) = flow.send(&payload).await {
            self.evict(target).await;
            return Err(err.into());
        }
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut incoming = self.incoming_rx.lock().await;
        incoming.recv().await.ok_or_else(|| {
            MasqueError::Disconnected("канал датаграмм MASQUE закрыт".to_owned()).into()
        })
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.flows.lock().await.clear();
        Ok(())
    }
}
