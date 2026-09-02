//! Клиент: соединение, аутентификация, выдача потоков и датаграмм.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::address::{Address, SocketAddress};
use penguin_core::id::OutboundId;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use tokio::task::JoinHandle;

use crate::auth::{self, AuthResponse, H3SendRequest, ServerRate};
use crate::config::Hysteria2Config;
use crate::congestion::brutal::BrutalRate;
use crate::error::{Hysteria2Error, Hysteria2Result};
use crate::frame::tcp;
use crate::session::tcp::TcpStream;
use crate::session::udp::UdpManager;
use crate::transport::quic::{self, QuicTransport};

/// Подключённый клиент Hysteria 2.
///
/// Один на профиль. Все соединения приложений идут потоками внутри одного
/// соединения QUIC — рукопожатие платится однажды.
pub struct Hysteria2Client {
    id: OutboundId,
    transport: QuicTransport,
    udp: Arc<UdpManager>,
    udp_enabled: bool,
    fast_open: bool,
    port_hopping: bool,

    /// Отправитель запросов HTTP/3 — держится живым намеренно.
    ///
    /// Выглядит неиспользуемым полем, но им не является: `h3` закрывает
    /// соединение, когда исчезает последний `SendRequest`. Уронив его сразу
    /// после аутентификации, мы получили бы закрытое соединение вместо
    /// рабочего.
    _h3: H3SendRequest,

    /// Задача, крутящая служебные потоки HTTP/3, — по той же причине.
    _h3_driver: JoinHandle<()>,
}

impl std::fmt::Debug for Hysteria2Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Client")
            .field("id", &self.id)
            .field("udp_enabled", &self.udp_enabled)
            .field("port_hopping", &self.port_hopping)
            .finish()
    }
}

impl Hysteria2Client {
    /// Подключается к серверу и проходит аутентификацию.
    pub async fn connect(
        id: OutboundId,
        config: &Hysteria2Config,
        dialer: Arc<dyn Dialer>,
    ) -> Hysteria2Result<Self> {
        config.validate()?;

        let endpoint = config.endpoint()?;
        let server_name = config.server_name()?;
        let server =
            resolve_server(&endpoint.host, endpoint.ports.first(), dialer.as_ref()).await?;

        let transport = quic::connect(config, dialer.as_ref(), server, &server_name).await?;

        let (mut h3_driver, mut h3_send) =
            h3::client::new(h3_quinn::Connection::new(transport.connection.clone()))
                .await
                .map_err(|e| Hysteria2Error::Auth(format!("HTTP/3 не поднялся: {e}")))?;

        let driver = tokio::spawn(async move {
            // Задача живёт, пока живо соединение: она крутит служебные потоки
            // HTTP/3, без которых `h3` считает соединение сломанным.
            let err = std::future::poll_fn(|cx| h3_driver.poll_close(cx)).await;
            tracing::debug!(%err, "служебное соединение HTTP/3 завершено");
        });

        let rx_bytes = config.bandwidth.down_bps()?.map_or(0, |bits| bits / 8);
        let response = auth::authenticate(&mut h3_send, &config.password, rx_bytes).await?;

        apply_server_rate(&response, transport.brutal_rate.as_ref());

        let udp = UdpManager::new(transport.connection.clone());

        if !response.udp_enabled {
            tracing::warn!("сервер не проксирует UDP — датаграммы пойдут мимо тоннеля");
        }

        Ok(Self {
            id,
            udp,
            udp_enabled: response.udp_enabled,
            fast_open: config.fast_open,
            port_hopping: endpoint.ports.is_hopping(),
            transport,
            _h3: h3_send,
            _h3_driver: driver,
        })
    }

    /// Время оборота до сервера.
    pub fn rtt(&self) -> std::time::Duration {
        self.transport.connection.rtt()
    }
}

/// Опускает скорость Brutal до предела, названного сервером.
///
/// Сервер не назначает скорость, а ограничивает её сверху: слать быстрее,
/// чем он готов принимать, значит терять разницу на его входе.
fn apply_server_rate(response: &AuthResponse, rate: Option<&BrutalRate>) {
    let Some(rate) = rate else {
        // Пользователь скорость не задал, работает BBR — ограничивать нечего.
        return;
    };

    match response.rate {
        ServerRate::Limited(server_bytes) if server_bytes > 0 => {
            let before = rate.get();
            rate.cap_to(server_bytes);
            if rate.get() < before {
                tracing::info!(
                    было = before,
                    стало = rate.get(),
                    "сервер ограничил скорость отдачи"
                );
            }
        }
        ServerRate::Auto => {
            // Сервер просит клиента работать обычным управлением перегрузкой.
            // Мы уже подключились с Brutal, а поменять управление у живого
            // соединения quinn не даёт — оставляем заданное пользователем и
            // говорим об этом вслух.
            tracing::warn!(
                "сервер просит автоматическое управление перегрузкой, но скорость задана \
                 в настройках — Brutal остаётся; уберите bandwidth.up, чтобы использовать BBR"
            );
        }
        ServerRate::Limited(_) | ServerRate::Unlimited | ServerRate::Unknown => {}
    }
}

/// Разрешает имя сервера в адрес.
async fn resolve_server(
    host: &Address,
    port: u16,
    dialer: &dyn Dialer,
) -> Hysteria2Result<SocketAddr> {
    match host {
        Address::Ip(ip) => Ok(SocketAddr::new(*ip, port)),
        Address::Domain(domain) => {
            let addresses = dialer
                .resolve(domain)
                .await
                .map_err(|e| Hysteria2Error::Resolve(format!("{domain}: {e}")))?;
            addresses
                .into_iter()
                .next()
                .map(|ip| SocketAddr::new(ip, port))
                .ok_or_else(|| Hysteria2Error::Resolve(domain.clone()))
        }
    }
}

#[async_trait]
impl Outbound for Hysteria2Client {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // Ровно то, что ответил сервер: соврать здесь означает, что
            // DNS-запросы уйдут в направление, которое их молча потеряет.
            udp: self.udp_enabled,
            multiplex: true,
            port_hopping: self.port_hopping,
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let (mut send, mut recv) = self
            .transport
            .connection
            .open_bi()
            .await
            .map_err(|e| Hysteria2Error::Disconnected(e.to_string()))?;

        let request = tcp::encode_request(&target.to_wire());
        send.write_all(&request)
            .await
            .map_err(|e| Hysteria2Error::Disconnected(e.to_string()))?;

        if self.fast_open {
            // Ответ прочитается сам при первом чтении из потока.
            return Ok(Box::new(TcpStream::fast_open(send, recv)));
        }

        let response = tcp::read_response(&mut recv)
            .await
            .map_err(|e| Hysteria2Error::Disconnected(e.to_string()))?;

        if !response.ok {
            return Err(Hysteria2Error::Refused {
                target: target.to_wire(),
                message: response.message,
            }
            .into());
        }

        Ok(Box::new(TcpStream::established(send, recv)))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        if !self.udp_enabled {
            return Err(Hysteria2Error::UdpDisabled.into());
        }
        Ok(Box::new(self.udp.open()))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.udp.shutdown().await;
        self.transport
            .connection
            .close(0u32.into(), b"closed by client");
        // Ждать завершения ввода-вывода эндпойнта обязательно: без этого
        // прощальный пакет может не успеть уйти, и сервер продержит сессию
        // до истечения тайм-аута.
        self.transport.endpoint.wait_idle().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthResponse;

    fn response(rate: ServerRate) -> AuthResponse {
        AuthResponse {
            udp_enabled: true,
            rate,
        }
    }

    #[test]
    fn server_limit_lowers_the_rate() {
        let rate = BrutalRate::new(12_500_000);
        apply_server_rate(&response(ServerRate::Limited(1_250_000)), Some(&rate));
        assert_eq!(rate.get(), 1_250_000);
    }

    #[test]
    fn server_limit_never_raises_the_rate() {
        // Сервер ограничивает сверху, а не назначает: щедрый ответ не повод
        // слать быстрее, чем позволяет канал пользователя.
        let rate = BrutalRate::new(1_250_000);
        apply_server_rate(&response(ServerRate::Limited(125_000_000)), Some(&rate));
        assert_eq!(rate.get(), 1_250_000);
    }

    #[test]
    fn unlimited_and_unknown_leave_the_rate_alone() {
        for answer in [ServerRate::Unlimited, ServerRate::Unknown, ServerRate::Auto] {
            let rate = BrutalRate::new(12_500_000);
            apply_server_rate(&response(answer), Some(&rate));
            assert_eq!(
                rate.get(),
                12_500_000,
                "ответ {answer:?} не должен менять скорость"
            );
        }
    }

    #[test]
    fn zero_limit_is_ignored() {
        // Ноль означает «без ограничений», а не «стоять».
        let rate = BrutalRate::new(12_500_000);
        apply_server_rate(&response(ServerRate::Limited(0)), Some(&rate));
        assert_eq!(rate.get(), 12_500_000);
    }

    #[tokio::test]
    async fn ip_server_needs_no_resolution() {
        struct NeverResolves;

        #[async_trait]
        impl Dialer for NeverResolves {
            async fn dial_tcp(
                &self,
                _addr: SocketAddr,
            ) -> Result<tokio::net::TcpStream, ProtocolError> {
                unreachable!("тест не открывает соединений")
            }
            async fn bind_udp(
                &self,
                _local: SocketAddr,
            ) -> Result<tokio::net::UdpSocket, ProtocolError> {
                unreachable!("тест не открывает сокетов")
            }
            async fn resolve(&self, _host: &str) -> Result<Vec<std::net::IpAddr>, ProtocolError> {
                panic!("числовой адрес не должен идти в резолвер");
            }
        }

        let host: Address = "203.0.113.5".parse().expect("адрес");
        let resolved = resolve_server(&host, 443, &NeverResolves)
            .await
            .expect("разбирается");
        assert_eq!(resolved.to_string(), "203.0.113.5:443");
    }
}
