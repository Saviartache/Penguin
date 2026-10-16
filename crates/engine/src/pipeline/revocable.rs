//! Поток и канал датаграмм, которые конвейер обрывает после смены правил ([`super::live`]).

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::WaitForCancellationFutureOwned;

use super::live::Lease;

/// Почему соединение оборвано.
const REASON: &str = "правило для соединения изменилось";

/// Поток, который обрывается ошибкой, как только его решение отозвано.
pub struct RevocableStream<S> {
    inner: S,
    revoked: Pin<Box<WaitForCancellationFutureOwned>>,
    _lease: Lease,
}

impl<S> RevocableStream<S> {
    /// Оборачивает поток записью соединения.
    pub fn new(inner: S, lease: Lease) -> Self {
        Self {
            inner,
            revoked: Box::pin(lease.revoked().clone().cancelled_owned()),
            _lease: lease,
        }
    }

    /// Ждать отзыва вместе с данными: отозванное соединение будится, даже если молчит.
    fn check(&mut self, cx: &mut Context<'_>) -> std::io::Result<()> {
        match self.revoked.as_mut().poll(cx) {
            Poll::Ready(()) => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                REASON,
            )),
            Poll::Pending => Ok(()),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RevocableStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.check(cx)?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RevocableStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.check(cx)?;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.check(cx)?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Канал датаграмм с той же судьбой: после отзыва следующая датаграмма откроет новый.
pub struct RevocableDatagram {
    inner: Box<dyn ProxyDatagram>,
    lease: Lease,
}

impl RevocableDatagram {
    /// Оборачивает канал записью соединения.
    pub fn new(inner: Box<dyn ProxyDatagram>, lease: Lease) -> Self {
        Self { inner, lease }
    }
}

#[async_trait]
impl ProxyDatagram for RevocableDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        if self.lease.revoked().is_cancelled() {
            return Err(ProtocolError::Disconnected(REASON.to_owned()));
        }
        self.inner.send_to(payload, target).await
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        tokio::select! {
            biased;
            () = self.lease.revoked().cancelled() => {
                Err(ProtocolError::Disconnected(REASON.to_owned()))
            }
            received = self.inner.recv_from() => received,
        }
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use penguin_core::id::OutboundId;
    use penguin_core::network::Network;
    use penguin_router::context::FlowContext;
    use penguin_router::decision::ResolvedDecision;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::super::live::LiveFlows;
    use super::*;

    fn lease(flows: &std::sync::Arc<LiveFlows>) -> Lease {
        let context = FlowContext::to_target(
            Network::Tcp,
            "10.0.0.2:50000".parse().expect("адрес"),
            "1.1.1.1:443".parse().expect("адрес"),
        );
        flows.register(context, ResolvedDecision::Tunnel(OutboundId::new("home")))
    }

    #[tokio::test]
    async fn a_silent_stream_wakes_up_with_an_error_when_revoked() {
        let flows = LiveFlows::new();
        let (inner, _peer) = tokio::io::duplex(64);
        let mut stream = RevocableStream::new(inner, lease(&flows));

        let reading = tokio::spawn(async move {
            let mut buffer = [0u8; 8];
            stream.read(&mut buffer).await
        });
        tokio::task::yield_now().await;
        flows.revise(|_| ResolvedDecision::Direct);

        let read = tokio::time::timeout(std::time::Duration::from_secs(1), reading)
            .await
            .expect("чтение не проснулось")
            .expect("задача");
        assert_eq!(
            read.expect_err("отзыв — ошибка").kind(),
            std::io::ErrorKind::ConnectionReset
        );
    }

    #[tokio::test]
    async fn an_untouched_stream_passes_data() {
        let flows = LiveFlows::new();
        let (inner, mut peer) = tokio::io::duplex(64);
        let mut stream = RevocableStream::new(inner, lease(&flows));

        stream.write_all(b"ping").await.expect("записано");
        let mut buffer = [0u8; 4];
        peer.read_exact(&mut buffer).await.expect("прочитано");
        assert_eq!(&buffer, b"ping");
    }
}
