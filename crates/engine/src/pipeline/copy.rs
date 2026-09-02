//! Двунаправленное копирование с учётом трафика и корректным закрытием половин.
//!
//! Учёт делается обёрткой вокруг потока, а не в цикле копирования. Причина
//! практическая: копированием занимается входящая точка (SOCKS5, TUN), и она
//! про счётчики движка ничего не знает — да и не должна. Обёртка же
//! возвращается ей как обычный поток.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use penguin_core::id::OutboundId;
use penguin_proto::stream::ProxyStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::metrics::counters::Metrics;

/// Поток, считающий проходящие через него байты.
///
/// «Вверх» и «вниз» здесь с точки зрения приложения: то, что оно **пишет** в
/// этот поток, ушло наружу (`uploaded`); то, что **читает**, пришло снаружи
/// (`downloaded`).
pub struct Metered {
    inner: Box<dyn ProxyStream>,
    metrics: Arc<Metrics>,
    outbound: OutboundId,
    closed: bool,
}

impl Metered {
    /// Оборачивает поток учётом.
    pub fn new(inner: Box<dyn ProxyStream>, metrics: Arc<Metrics>, outbound: OutboundId) -> Self {
        metrics.connection_opened(&outbound);
        Self {
            inner,
            metrics,
            outbound,
            closed: false,
        }
    }
}

impl Drop for Metered {
    fn drop(&mut self) {
        // Закрытие учитывается ровно один раз, сколько бы раз ни звали
        // `poll_shutdown`: иначе счётчик живых соединений уходит в минус.
        if !self.closed {
            self.metrics.connection_closed();
        }
    }
}

impl AsyncRead for Metered {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        let read = buf.filled().len() - before;

        if read > 0 {
            self.metrics.add_downloaded(&self.outbound, read as u64);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Metered {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let written = ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
        if written > 0 {
            self.metrics.add_uploaded(&self.outbound, written as u64);
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = ready!(Pin::new(&mut self.inner).poll_shutdown(cx));
        if !self.closed {
            self.closed = true;
            self.metrics.connection_closed();
        }
        Poll::Ready(result)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn wrap(inner: Box<dyn ProxyStream>) -> (Metered, Arc<Metrics>) {
        let metrics = Metrics::new();
        let metered = Metered::new(inner, Arc::clone(&metrics), OutboundId::new("home"));
        (metered, metrics)
    }

    #[tokio::test]
    async fn counts_both_directions() {
        let (ours, mut theirs) = tokio::io::duplex(1024);
        let (mut metered, metrics) = wrap(Box::new(ours));

        metered
            .write_all("запрос".as_bytes())
            .await
            .expect("записано");
        theirs
            .write_all("ответ подлиннее".as_bytes())
            .await
            .expect("записано");

        let mut buf = vec![0u8; "ответ подлиннее".len()];
        metered.read_exact(&mut buf).await.expect("прочитано");

        let traffic = metrics.total();
        assert_eq!(traffic.uploaded, "запрос".len() as u64);
        assert_eq!(traffic.downloaded, "ответ подлиннее".len() as u64);
    }

    #[tokio::test]
    async fn connection_is_counted_once() {
        let (ours, _theirs) = tokio::io::duplex(1024);
        let (metered, metrics) = wrap(Box::new(ours));
        assert_eq!(metrics.live_connections(), 1);
        assert_eq!(metrics.total().connections, 1);

        drop(metered);
        assert_eq!(metrics.live_connections(), 0);
    }

    #[tokio::test]
    async fn shutdown_then_drop_does_not_double_count() {
        // `poll_shutdown` и `Drop` оба закрывают соединение; счётчик живых
        // должен уменьшиться ровно один раз.
        let (ours, _theirs) = tokio::io::duplex(1024);
        let (mut metered, metrics) = wrap(Box::new(ours));

        metered.shutdown().await.expect("закрыто");
        assert_eq!(metrics.live_connections(), 0);
        drop(metered);
        assert_eq!(metrics.live_connections(), 0);
    }

    #[tokio::test]
    async fn per_outbound_accounting_works() {
        let (ours, _theirs) = tokio::io::duplex(1024);
        let (mut metered, metrics) = wrap(Box::new(ours));
        metered.write_all(b"12345").await.expect("записано");

        let rows = metrics.per_outbound();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outbound, "home");
        assert_eq!(rows[0].traffic.uploaded, 5);
    }
}
