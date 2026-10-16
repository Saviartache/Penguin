//! Раздача входящих датаграмм по запросам (RFC 9297, §2.1).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::mpsc;

/// Предел очереди получателя; лишние датаграммы теряются.
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

    /// Кладёт датаграмму в очередь потока; чужие и лишние теряются.
    pub(super) fn route(&self, stream_id: u64, payload: Bytes) {
        if let Some(tx) = self.lock().get(&stream_id) {
            let _ = tx.try_send(payload);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, mpsc::Sender<Bytes>>> {
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
