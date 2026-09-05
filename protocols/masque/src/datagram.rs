//! [`ProxyDatagram`] поверх `CONNECT-UDP`: канал с произвольным адресом на
//! каждой посылке, собранный из каналов `CONNECT-UDP` с ровно одним адресом
//! каждый.
//!
//! # Почему тут кэш, а не один канал
//!
//! RFC 9298 привязывает один поток `CONNECT-UDP` к одному адресу назначения:
//! адрес — часть пути запроса (§2), а не поле на каждой датаграмме. Но
//! [`ProxyDatagram::send_to`] обещает противоположное — адрес приходит с
//! каждым пакетом, потому что выше по стеку одна UDP-ассоциация (например,
//! `SOCKS5 UDP ASSOCIATE`) может слать в несколько мест за свою жизнь: так
//! резолвер стучится в несколько DNS-серверов через одно и то же гнездо.
//!
//! Разрыв закрывается здесь: [`MasqueDatagram`] держит по каналу
//! [`Flow`] на каждый увиденный адрес и открывает новый только при первом
//! обращении к нему — так же, как открылось бы новое TCP-соединение на новый
//! хост. Все каналы делят одно и то же соединение HTTP/3 ([`Session`]) — оно
//! одно на всё направление, а не на одну ассоциацию.

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

/// Сколько датаграмм может ждать разбора, пока их не забрал `recv_from`.
///
/// Не пропускная способность канала — она ограничена самим QUIC — а запас на
/// случай, когда несколько целей отвечают одновременно, а читатель занят
/// чем-то ещё в тот же момент.
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

    /// Убирает канал из кэша — вызывается, когда отправка через него не
    /// удалась: держать мёртвый канал означало бы, что все следующие пакеты
    /// на этот адрес тоже молча терялись бы.
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
            // Отправители живут в каналах `Flow`: пустая очередь при закрытом
            // канале означает, что сеанс закрыт целиком.
            MasqueError::Disconnected("канал датаграмм MASQUE закрыт".to_owned()).into()
        })
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.flows.lock().await.clear();
        Ok(())
    }
}
