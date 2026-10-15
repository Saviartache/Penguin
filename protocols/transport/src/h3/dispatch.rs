//! Раздача входящих датаграмм HTTP/3 по запросам.
//!
//! Датаграммы приходят по общему соединению QUIC; номер потока внутри
//! каждой говорит, какому запросу она принадлежит (RFC 9297, §2.1).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::mpsc;

/// Сколько датаграмм ждёт получателя, прежде чем лишние теряются.
///
/// Потеря — обычное дело для датаграмм; копить без предела значило бы, что
/// забытый получатель съедает память.
const QUEUE: usize = 256;

/// Таблица «поток → очередь».
#[derive(Debug, Default)]
pub(super) struct Router {
    routes: Mutex<HashMap<u64, mpsc::Sender<Bytes>>>,
}

impl Router {
    /// Заводит очередь для потока `stream_id`.
    pub(super) fn register(self: &Arc<Self>, stream_id: u64) -> DatagramReceiver {
        let (tx, rx) = mpsc::channel(QUEUE);
        self.lock().insert(stream_id, tx);
        DatagramReceiver {
            rx,
            stream_id,
            router: Arc::clone(self),
        }
    }

    /// Кладёт датаграмму в очередь её потока. Чужие и лишние теряются:
    /// RFC 9297, §2.1 разрешает молча отбросить датаграмму без потока.
    pub(super) fn route(&self, stream_id: u64, payload: Bytes) {
        if let Some(tx) = self.lock().get(&stream_id) {
            // Очередь полна или получатель ушёл — датаграмма теряется.
            let _ = tx.try_send(payload);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, mpsc::Sender<Bytes>>> {
        // Отравление не страшно: таблица не бывает в полуизменённом виде.
        self.routes.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Входящие датаграммы одного запроса.
#[derive(Debug)]
pub struct DatagramReceiver {
    rx: mpsc::Receiver<Bytes>,
    stream_id: u64,
    router: Arc<Router>,
}

impl DatagramReceiver {
    /// Следующая датаграмма. `None` — соединение закрыто.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.recv().await
    }
}

impl Drop for DatagramReceiver {
    fn drop(&mut self) {
        self.router.lock().remove(&self.stream_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn datagrams_reach_only_their_stream() {
        let router = Arc::new(Router::default());
        let mut first = router.register(0);
        let mut second = router.register(4);

        router.route(4, Bytes::from_static(b"b"));
        router.route(0, Bytes::from_static(b"a"));
        router.route(8, Bytes::from_static(b"nobody"));

        assert_eq!(first.recv().await.as_deref(), Some(&b"a"[..]));
        assert_eq!(second.recv().await.as_deref(), Some(&b"b"[..]));
    }

    #[test]
    fn a_dropped_receiver_is_forgotten() {
        let router = Arc::new(Router::default());
        drop(router.register(0));
        assert!(router.lock().is_empty());
    }
}
