//! `Inbound` — трейт источника соединений. У TUN и SOCKS5 он один и тот же.
//!
//! Точнее, общий у них не источник, а то, что они делают с полученным
//! соединением: спрашивают, куда его вести, и получают готовый поток. Кто
//! отвечает на этот вопрос — маршрутизатор, тоннель или заглушка в тесте —
//! входящей точке не важно.

use std::net::SocketAddr;

use async_trait::async_trait;
use penguin_core::address::SocketAddress;
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
    /// TCP или UDP.
    pub network: Network,
}

/// Тот, кто решает судьбу соединения и открывает его.
///
/// В работающем клиенте это движок: он спрашивает маршрутизатор и открывает
/// соединение через нужное направление. В тестах — заглушка на две строки.
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
