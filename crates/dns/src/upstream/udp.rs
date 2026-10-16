//! DNS поверх UDP: открытый текст, но безопасный внутри тоннеля; мимо тоннеля есть [`super::dot`].

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::dialer::Dialer;
use tokio::net::UdpSocket;

use super::{Sockets, Upstream, socket_error};
use crate::config::UPSTREAM_TIMEOUT;
use crate::error::{DnsError, DnsResult};

/// Наибольший ответ по UDP: сверх 512 байт RFC 1035 с запасом на EDNS0.
const MAX_RESPONSE: usize = 4096;

/// DNS поверх UDP.
#[derive(Clone)]
pub struct UdpUpstream {
    server: SocketAddr,
    sockets: Sockets,
}

impl std::fmt::Debug for UdpUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpUpstream")
            .field("server", &self.server)
            .field("protected", &self.sockets.is_some())
            .finish()
    }
}

impl UdpUpstream {
    /// Создаёт апстрим.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            sockets: None,
        }
    }

    /// Берёт сокеты у набирателя: мимо собственного тоннеля.
    pub fn through(mut self, sockets: Arc<dyn Dialer>) -> Self {
        self.sockets = Some(sockets);
        self
    }

    /// Разбирает адрес из настроек; порт по умолчанию 53.
    pub fn parse(address: &str) -> DnsResult<Self> {
        let address = address.trim();
        let with_port = if address.contains(':') {
            address.to_owned()
        } else {
            format!("{address}:53")
        };

        let server: SocketAddr = with_port
            .parse()
            .map_err(|_| DnsError::Config(format!("не разбирается адрес DNS `{address}`")))?;
        Ok(Self::new(server))
    }

    /// Адрес сервера.
    pub fn server(&self) -> SocketAddr {
        self.server
    }
}

#[async_trait]
impl Upstream for UdpUpstream {
    fn describe(&self) -> String {
        format!("udp://{}", self.server)
    }

    async fn query(&self, request: &[u8]) -> DnsResult<Vec<u8>> {
        // Сокет на запрос: новый порт затрудняет подделку ответа.
        let local = if self.server.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };

        let socket = match &self.sockets {
            Some(sockets) => sockets.bind_udp(local).await.map_err(socket_error)?,
            None => UdpSocket::bind(local).await?,
        };
        socket.connect(self.server).await?;
        socket.send(request).await?;

        let mut buffer = [0u8; MAX_RESPONSE];
        let len = tokio::time::timeout(UPSTREAM_TIMEOUT, socket.recv(&mut buffer))
            .await
            .map_err(|_| DnsError::Upstream(format!("{} не ответил", self.server)))??;

        Ok(buffer[..len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_the_default_port() {
        let upstream = UdpUpstream::parse("1.1.1.1").expect("разбирается");
        assert_eq!(upstream.server().port(), 53);
    }

    #[test]
    fn keeps_an_explicit_port() {
        let upstream = UdpUpstream::parse("1.1.1.1:5353").expect("разбирается");
        assert_eq!(upstream.server().port(), 5353);
    }

    #[test]
    fn handles_ipv6() {
        let upstream = UdpUpstream::parse("[2001:4860:4860::8888]:53").expect("разбирается");
        assert!(upstream.server().is_ipv6());
    }

    #[test]
    fn rejects_garbage() {
        assert!(UdpUpstream::parse("не адрес").is_err());
        assert!(UdpUpstream::parse("").is_err());
    }

    #[test]
    fn describes_itself() {
        let upstream = UdpUpstream::parse("8.8.8.8").expect("разбирается");
        assert_eq!(upstream.describe(), "udp://8.8.8.8:53");
    }

    #[tokio::test]
    async fn silent_server_times_out_instead_of_hanging() {
        // Свой сокет, который не отвечает: чужой адрес на 53-м порту перехватит
        // подменённый резолвер системы.
        let silent = UdpSocket::bind("127.0.0.1:0").await.expect("сокет");
        let upstream = UdpUpstream::new(silent.local_addr().expect("адрес"));
        let started = std::time::Instant::now();

        let result = upstream.query(&[0u8; 12]).await;
        assert!(
            result.is_err(),
            "молчащий сервер не должен считаться ответившим"
        );
        assert!(
            started.elapsed() < UPSTREAM_TIMEOUT * 3,
            "ожидание затянулось"
        );
    }
}
