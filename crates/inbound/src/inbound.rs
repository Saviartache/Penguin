//! Трейты входящей точки и того, кто решает судьбу её соединений.

use std::net::SocketAddr;

use async_trait::async_trait;
use penguin_core::address::{Address, SocketAddress};
use penguin_core::network::Network;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;

/// Кто и куда собрался.
#[derive(Debug, Clone)]
pub struct InboundRequest {
    /// Откуда пришло соединение.
    pub source: SocketAddr,
    /// Куда оно собирается.
    pub target: SocketAddress,
    /// Имя, опознанное в потоке: только для правил, соединение идёт на `target`.
    pub sniffed: Option<Address>,
    /// TCP или UDP.
    pub network: Network,
}

/// Тот, кто решает судьбу соединения и открывает его (движок или заглушка в тесте).
#[async_trait]
pub trait InboundHandler: Send + Sync + 'static {
    /// Открывает поток до цели.
    async fn open_tcp(
        &self,
        request: &InboundRequest,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError>;

    /// Открывает датаграммный канал.
    async fn open_udp(
        &self,
        request: &InboundRequest,
    ) -> Result<Box<dyn ProxyDatagram>, ProtocolError>;
}

/// Входящая точка: слушает и обслуживает соединения, пока её не остановят.
#[async_trait]
pub trait Inbound: Send + Sync + 'static {
    /// Имя для журнала: `socks5`, `http`, `tun`.
    fn name(&self) -> &'static str;

    /// Адрес, на котором точка слушает.
    fn local_addr(&self) -> Option<SocketAddr>;

    /// Работает, пока не отменят.
    async fn serve(self: Box<Self>, cancel: tokio_util::sync::CancellationToken);
}
