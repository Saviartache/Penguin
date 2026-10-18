//! Поток и канал датаграмм, считающие трафик: обёртки, чтобы входящие точки не знали о счётчиках.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;
use penguin_core::stats::Counters;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::metrics::counters::Metrics;

/// Поток, считающий проходящие через него байты.
///
/// Запись приложения — `uploaded`, чтение — `downloaded`.
pub struct Metered {
    inner: Box<dyn ProxyStream>,
    metrics: Arc<Metrics>,
    outbound: Arc<Counters>,
    closed: bool,
}

impl Metered {
    /// Оборачивает поток учётом.
    pub fn new(inner: Box<dyn ProxyStream>, metrics: Arc<Metrics>, outbound: OutboundId) -> Self {
        metrics.connection_opened(&outbound);
        let outbound = metrics.outbound(&outbound);
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
            self.metrics.add_downloaded_to(&self.outbound, read as u64);
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
            self.metrics.add_uploaded_to(&self.outbound, written as u64);
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

/// Канал датаграмм, считающий полезную нагрузку: отправка — `uploaded`, приём — `downloaded`.
pub struct MeteredDatagram {
    inner: Box<dyn ProxyDatagram>,
    metrics: Arc<Metrics>,
    outbound: Arc<Counters>,
}

impl MeteredDatagram {
    /// Оборачивает канал учётом.
    pub fn new(
        inner: Box<dyn ProxyDatagram>,
        metrics: Arc<Metrics>,
        outbound: &OutboundId,
    ) -> Self {
        let outbound = metrics.outbound(outbound);
        Self {
            inner,
            metrics,
            outbound,
        }
    }
}

#[async_trait]
impl ProxyDatagram for MeteredDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let len = payload.len() as u64;
        self.inner.send_to(payload, target).await?;
        self.metrics.add_uploaded_to(&self.outbound, len);
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let received = self.inner.recv_from().await?;
        self.metrics
            .add_downloaded_to(&self.outbound, received.0.len() as u64);
        Ok(received)
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Канал, возвращающий отправленное.
    struct Echo(tokio::sync::Mutex<Vec<(Bytes, SocketAddress)>>);

    #[async_trait]
    impl ProxyDatagram for Echo {
        async fn send_to(
            &self,
            payload: Bytes,
            target: &SocketAddress,
        ) -> Result<(), ProtocolError> {
            self.0.lock().await.push((payload, target.clone()));
            Ok(())
        }

        async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
            self.0
                .lock()
                .await
                .pop()
                .ok_or_else(|| ProtocolError::Disconnected("пусто".to_owned()))
        }
    }

    #[tokio::test]
    async fn datagrams_are_counted_both_ways() {
        let metrics = Metrics::new();
        let channel = MeteredDatagram::new(
            Box::new(Echo(Default::default())),
            Arc::clone(&metrics),
            &OutboundId::new("home"),
        );
        let target: SocketAddress = "1.1.1.1:443".parse().expect("адрес");

        channel
            .send_to(Bytes::from_static(b"quic"), &target)
            .await
            .expect("отправлено");
        channel.recv_from().await.expect("принято");

        let traffic = metrics.total();
        assert_eq!(traffic.uploaded, 4);
        assert_eq!(traffic.downloaded, 4);
        assert_eq!(traffic.connections, 0);
    }

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
