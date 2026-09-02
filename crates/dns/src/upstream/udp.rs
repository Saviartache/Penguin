//! Обычный DNS поверх UDP.
//!
//! Виден провайдеру целиком: и имя, и ответ идут открытым текстом. Тем не
//! менее это **обязательный** способ, и вот почему.
//!
//! Загрузочное разрешение имени сервера происходит до того, как тоннель
//! поднят, — шифровать его нечем и негде. А основное разрешение в режиме
//! `resolve` идёт уже **через тоннель**, и там открытый UDP ничего не
//! раскрывает: наружу он выходит с той стороны.
//!
//! Прятать от провайдера имя самого VPN-сервера имеет смысл, и для этого есть
//! [`super::dot`].

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use super::Upstream;
use crate::error::{DnsError, DnsResult};

/// Сколько ждать ответа.
///
/// Две секунды: дольше ждать бессмысленно — приложение к этому моменту само
/// перепошлёт запрос.
const TIMEOUT: Duration = Duration::from_secs(2);

/// Наибольший ответ, который принимается по UDP.
///
/// 512 байт — предел из RFC 1035, но с EDNS0 ответы бывают крупнее. Четыре
/// килобайта покрывают всё, что реально приходит.
const MAX_RESPONSE: usize = 4096;

/// DNS поверх UDP.
#[derive(Debug, Clone)]
pub struct UdpUpstream {
    server: SocketAddr,
}

impl UdpUpstream {
    /// Создаёт апстрим.
    pub fn new(server: SocketAddr) -> Self {
        Self { server }
    }

    /// Разбирает адрес из настроек.
    ///
    /// Порт можно не писать: у DNS он всегда 53.
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
        // Сокет на каждый запрос: порт при этом каждый раз новый, и подделать
        // ответ становится заметно труднее — угадывать надо и порт, и
        // идентификатор.
        let local: SocketAddr = if self.server.is_ipv4() {
            "0.0.0.0:0".parse()
        } else {
            "[::]:0".parse()
        }
        .map_err(|_| DnsError::Config("не разбирается локальный адрес".to_owned()))?;

        let socket = UdpSocket::bind(local).await?;
        socket.connect(self.server).await?;
        socket.send(request).await?;

        let mut buffer = vec![0u8; MAX_RESPONSE];
        let len = tokio::time::timeout(TIMEOUT, socket.recv(&mut buffer))
            .await
            .map_err(|_| DnsError::Upstream(format!("{} не ответил", self.server)))??;

        buffer.truncate(len);
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_the_default_port() {
        // Пользователь пишет `1.1.1.1`, и заставлять его дописывать `:53`
        // незачем.
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
        // Описание попадает в журнал и в диагностику: по нему видно, куда
        // именно ушёл запрос.
        let upstream = UdpUpstream::parse("8.8.8.8").expect("разбирается");
        assert_eq!(upstream.describe(), "udp://8.8.8.8:53");
    }

    #[tokio::test]
    async fn silent_server_times_out_instead_of_hanging() {
        // Адрес из отведённой под документацию подсети (RFC 5737): туда
        // ничего не идёт и оттуда ничего не приходит.
        let upstream = UdpUpstream::parse("192.0.2.1").expect("разбирается");
        let started = std::time::Instant::now();

        let result = upstream.query(&[0u8; 12]).await;
        assert!(
            result.is_err(),
            "молчащий сервер не должен считаться ответившим"
        );
        assert!(started.elapsed() < TIMEOUT * 3, "ожидание затянулось");
    }
}
