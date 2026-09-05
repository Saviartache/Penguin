//! Направление через сервер Brook.
//!
//! Постоянного соединения у протокола нет: каждый поток приложения — это
//! новое TCP-соединение со своим рукопожатием, как у Shadowsocks и Trojan.
//! Рукопожатие устроено так же для всех трёх режимов переноса ([`Transport`]);
//! разница только в том, как байты доходят до сервера — напрямую, через
//! WebSocket или через WebSocket внутри TLS.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::address::{Address, SocketAddress};
use penguin_core::id::OutboundId;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::connect;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use penguin_transport::deadline;
use penguin_transport::tls::TlsClient;
use penguin_transport::ws;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{BrookConfig, Transport};
use crate::datagram::BrookDatagram;
use crate::error::{BrookError, BrookResult};
use crate::frame::cipher::Cipher;
use crate::frame::clock::now_unix;
use crate::frame::nonce::{NONCE_LEN, Nonce};
use crate::frame::tcp;
use crate::stream::BrookStream;

/// Исходящее направление через сервер Brook.
pub struct BrookOutbound {
    id: OutboundId,
    config: BrookConfig,
    /// Хост сервера, разобранный один раз при сборке.
    host: Address,
    /// Порт сервера.
    port: u16,
    /// Пароль байтами: и HKDF, и подпись `Debug` работают с ним, не со
    /// строкой.
    password: Vec<u8>,
    /// Собранный клиент TLS. `Some` только при `transport = "wss"`.
    tls: Option<TlsClient>,
    dialer: Arc<dyn Dialer>,
}

impl std::fmt::Debug for BrookOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrookOutbound")
            .field("id", &self.id)
            .field("config", &self.config)
            .finish()
    }
}

impl BrookOutbound {
    /// Собирает направление. Соединения при этом не открывается: у Brook его
    /// и не бывает постоянного.
    pub fn new(id: OutboundId, config: BrookConfig, dialer: Arc<dyn Dialer>) -> BrookResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;

        let tls = match config.transport {
            Transport::Wss => Some(TlsClient::new(&config.tls, &host, config.default_alpn())?),
            Transport::Direct | Transport::Ws => None,
        };

        Ok(Self {
            id,
            password: config.password.clone().into_bytes(),
            config,
            host,
            port,
            tls,
            dialer,
        })
    }

    /// Соединение до сервера вместе с переносом, но без рукопожатия Brook.
    async fn carry(&self) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let plain = connect::dial(&*self.dialer, &self.host, self.port).await?;

        let secure: Box<dyn ProxyStream> = match &self.tls {
            Some(tls) => Box::new(tls.connect(plain).await.map_err(BrookError::from)?),
            None => Box::new(plain),
        };

        Ok(match self.config.transport {
            Transport::Direct => secure,
            Transport::Ws | Transport::Wss => {
                let request = ws::Request::new(
                    self.config.ws_host().map_err(ProtocolError::from)?,
                    self.config.ws_path().to_owned(),
                );
                Box::new(
                    ws::connect(secure, &request)
                        .await
                        .map_err(BrookError::from)?,
                )
            }
        })
    }

    /// Проводит рукопожатие Brook поверх уже открытого переноса.
    ///
    /// Обе стороны бросают свой нонс, выводят из него ключ на отправку, и
    /// клиент первым же куском называет адрес назначения. Дальше остаётся
    /// поток приложения — [`BrookStream`].
    async fn handshake(
        &self,
        mut io: Box<dyn ProxyStream>,
        target: &SocketAddress,
    ) -> Result<BrookStream<Box<dyn ProxyStream>>, ProtocolError> {
        let client_nonce = random_nonce();
        let mut send = Cipher::new(&self.password, client_nonce).map_err(ProtocolError::from)?;

        let first = tcp::first_fragment(now_unix(), target).map_err(ProtocolError::from)?;
        let sealed_first = tcp::seal_fragment(&mut send, &first).map_err(ProtocolError::from)?;

        let server_nonce = deadline::handshake::<_, BrookError>("рукопожатие Brook", async {
            io.write_all(&client_nonce).await?;
            io.write_all(&sealed_first).await?;
            io.flush().await?;

            let mut server_nonce: Nonce = [0u8; NONCE_LEN];
            match io.read_exact(&mut server_nonce).await {
                Ok(_) => Ok(server_nonce),
                // Эталон отвечает своим нонсом только после того, как принял
                // наш пароль и метку времени. Не дождавшись двенадцати байт,
                // отличить «неверный пароль» от «часы разошлись» нечем — обе
                // причины сервер лечит одинаково: закрывает соединение молча
                // (см. документ `crate::error`).
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    Err(BrookError::HandshakeRejected)
                }
                Err(err) => Err(BrookError::Io(err)),
            }
        })
        .await?;

        let recv = Cipher::new(&self.password, server_nonce).map_err(ProtocolError::from)?;
        Ok(BrookStream::new(io, send, recv))
    }
}

#[async_trait]
impl Outbound for BrookOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // Не то, что стоит в настройках, а то, что выйдет на самом деле:
            // у `ws` и `wss` датаграмм нет вовсе, и обещать их значит терять
            // запросы DNS молча.
            udp: self.config.udp_works(),
            // Своя пара нонсов на каждое соединение, постоянного канала нет.
            multiplex: false,
            port_hopping: false,
            // Имя уезжает серверу доменом и разрешается на его стороне.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let io = self.carry().await?;
        let stream = self.handshake(io, target).await?;
        Ok(Box::new(stream))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        if !self.config.udp_works() {
            return Err(BrookError::UdpDisabled.into());
        }

        // Адрес сервера нужен числовым: датаграммы шлются сокетом, а он имён
        // не знает. Разрешает имя `Dialer` — мимо тоннеля, как и всё
        // остальное.
        let server = first_address(&*self.dialer, &self.host, self.port).await?;
        let local = SocketAddr::new(
            if server.is_ipv6() {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            },
            0,
        );

        let socket = self.dialer.bind_udp(local).await?;
        Ok(Box::new(BrookDatagram::new(
            socket,
            server,
            self.password.clone(),
        )))
    }
}

/// Свежий нонс: соль для ключа и первое значение счётчика разом.
fn random_nonce() -> Nonce {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill(&mut nonce);
    nonce
}

/// Первый адрес сервера, какой удалось получить.
///
/// Перебирать их, как это делает [`connect::dial`], здесь нечем: у UDP нет
/// «не удалось подключиться», по которому можно было бы понять, что адрес не
/// тот. Берётся первый — тот же, к которому подключился бы TCP.
async fn first_address(
    dialer: &dyn Dialer,
    host: &Address,
    port: u16,
) -> Result<SocketAddr, ProtocolError> {
    let addresses = connect::resolve(dialer, host, port).await?;
    addresses.into_iter().next().ok_or_else(|| {
        ProtocolError::Connect(format!("до `{host}:{port}` не нашлось ни одного адреса"))
    })
}

#[cfg(test)]
mod tests {
    use tokio::net::{TcpStream, UdpSocket};

    use super::*;

    /// Звонящий, который никуда не звонит.
    #[derive(Debug)]
    struct NoDialer;

    #[async_trait]
    impl Dialer for NoDialer {
        async fn dial_tcp(&self, _addr: SocketAddr) -> Result<TcpStream, ProtocolError> {
            Err(ProtocolError::Unsupported("сеть в тесте"))
        }

        async fn bind_udp(&self, _local: SocketAddr) -> Result<UdpSocket, ProtocolError> {
            Err(ProtocolError::Unsupported("сеть в тесте"))
        }

        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
            Err(ProtocolError::Unsupported("сеть в тесте"))
        }
    }

    fn config() -> BrookConfig {
        BrookConfig {
            server: "example.com:9999".to_owned(),
            password: "secret".to_owned(),
            ..BrookConfig::default()
        }
    }

    fn outbound(config: BrookConfig) -> BrookResult<BrookOutbound> {
        BrookOutbound::new(
            OutboundId::from("тест".to_owned()),
            config,
            Arc::new(NoDialer),
        )
    }

    #[tokio::test]
    async fn capabilities_follow_the_transport_not_just_the_flag() {
        let direct = outbound(config()).expect("собирается").capabilities();
        assert!(direct.udp);
        assert!(!direct.multiplex);
        assert!(direct.remote_dns);
        assert!(!direct.port_hopping);

        let ws = outbound(BrookConfig {
            transport: Transport::Ws,
            ..config()
        })
        .expect("собирается")
        .capabilities();
        assert!(!ws.udp, "у ws датаграмм нет вовсе");
    }

    #[tokio::test]
    async fn udp_turned_off_is_refused_and_not_silently_dropped() {
        let outbound = outbound(BrookConfig {
            udp: false,
            ..config()
        })
        .expect("собирается");
        assert!(!outbound.capabilities().udp);
        assert!(outbound.bind_udp().await.is_err());
    }

    #[tokio::test]
    async fn bad_settings_are_caught_before_any_connection() {
        assert!(
            outbound(BrookConfig {
                password: String::new(),
                ..config()
            })
            .is_err()
        );
    }

    #[test]
    fn wss_builds_its_tls_client_once_at_construction() {
        let built = outbound(BrookConfig {
            transport: Transport::Wss,
            ..config()
        })
        .expect("собирается");
        assert!(built.tls.is_some());

        let direct = outbound(config()).expect("собирается");
        assert!(direct.tls.is_none());
    }
}
