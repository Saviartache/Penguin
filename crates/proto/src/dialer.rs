//! `Dialer` — выход протокола наружу в обход собственного тоннеля.
//! Сокеты выдаёт он, а не протокол: иначе трафик к серверу вернулся бы в TUN.

use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};

use crate::error::ProtocolError;

/// Выход наружу мимо тоннеля; реализацию даёт `penguin-engine`.
#[async_trait]
pub trait Dialer: Send + Sync + 'static {
    /// Открывает TCP-соединение мимо тоннеля.
    async fn dial_tcp(&self, addr: SocketAddr) -> Result<TcpStream, ProtocolError>;

    /// Открывает UDP-сокет мимо тоннеля; `local` задаёт семейство адресов.
    async fn bind_udp(&self, local: SocketAddr) -> Result<UdpSocket, ProtocolError>;

    /// Разрешает имя сервера мимо тоннеля (системный резолвер пошёл бы в TUN).
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ProtocolError>;
}
