//! Направление через сервер Trojan.
//!
//! Мультиплексирования у Trojan нет: каждое подключение — свой поток со своим
//! заголовком. По `tcp` и `grpc` это своё соединение TLS; по `xhttp` — свой
//! поток HTTP/3 внутри общего соединения QUIC. Собрано заранее ровно то, что
//! дорого собирать заново: настройки TLS и отпечаток пароля.

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
use penguin_transport::tls::TlsClient;
use penguin_transport::xhttp::{XhttpClient, XhttpTarget};
use penguin_transport::{carrier, deadline};
use tokio::io::AsyncWriteExt;

use crate::config::TrojanConfig;
use crate::datagram::TrojanDatagram;
use crate::error::{TrojanError, TrojanResult};
use crate::frame::request::{self, CMD_CONNECT, CMD_UDP, HASH_LEN};

/// Адрес в заголовке команды `UDP`.
///
/// Своего адреса у неё нет: настоящий стоит на каждой датаграмме отдельно.
/// Нули — то, что шлют остальные клиенты; сервер это поле при `UDP` не
/// использует.
const UDP_PLACEHOLDER: &str = "0.0.0.0";

/// Исходящее направление через сервер Trojan.
pub struct TrojanOutbound {
    id: OutboundId,
    config: TrojanConfig,
    /// Хост сервера, разобранный один раз при сборке.
    host: Address,
    /// Порт сервера.
    port: u16,
    /// Отпечаток пароля: считается один раз, а не на каждый поток.
    password: [u8; HASH_LEN],
    tls: TlsClient,
    /// Клиент XHTTP — только у `transport = "xhttp"`.
    xhttp: Option<XhttpClient>,
    dialer: Arc<dyn Dialer>,
}

impl std::fmt::Debug for TrojanOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanOutbound")
            .field("id", &self.id)
            .field("config", &self.config)
            .finish()
    }
}

impl TrojanOutbound {
    /// Собирает направление.
    ///
    /// Соединения при этом не открывается: подключается направление на каждый
    /// поток заново.
    pub fn new(
        id: OutboundId,
        config: TrojanConfig,
        dialer: Arc<dyn Dialer>,
    ) -> TrojanResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;
        let tls = TlsClient::new(&config.tls, &host, config.transport.default_alpn())?;
        let authority = config.host()?;
        let xhttp = config.transport.is_quic().then(|| {
            let target = XhttpTarget {
                host: host.clone(),
                port,
                tls: config.tls.clone(),
                authority,
                path: config.path().to_owned(),
            };
            XhttpClient::new(target, Arc::clone(&dialer))
        });

        Ok(Self {
            id,
            password: request::password_hash(&config.password),
            config,
            host,
            port,
            tls,
            xhttp,
            dialer,
        })
    }

    /// Открывает поток до сервера: TLS и, если он выбран, перенос поверх него.
    async fn open(&self) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        if let Some(xhttp) = &self.xhttp {
            return Ok(Box::new(xhttp.open().await.map_err(TrojanError::from)?));
        }
        let plain = connect::dial(&*self.dialer, &self.host, self.port).await?;
        let secure = self.tls.connect(plain).await.map_err(TrojanError::from)?;
        let authority = self.config.host()?;
        Ok(carrier::wrap(
            secure,
            self.config.transport,
            &authority,
            self.config.path(),
        )
        .await
        .map_err(TrojanError::from)?)
    }

    /// Открывает поток и отправляет заголовок.
    async fn start(
        &self,
        command: u8,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let mut io = self.open().await?;
        let header = request::header(&self.password, command, target)?;

        deadline::handshake::<_, TrojanError>("заголовок Trojan", async {
            io.write_all(&header).await?;
            io.flush().await?;
            Ok(())
        })
        .await?;

        Ok(io)
    }

    /// Проверяет, что сервер на месте и предъявляет ожидаемый сертификат.
    ///
    /// Пароль здесь не проверяется, и проверить его нечем: сервер не отвечает
    /// на заголовок ничем, а не узнав отпечаток — молча отдаёт наши байты
    /// сайту, за который себя выдаёт. Это замысел протокола, а не пробел
    /// реализации (см. документ крейта).
    ///
    /// Поэтому проверяется то, что можно проверить, никого не беспокоя:
    /// отвечает ли сервер и сходится ли его сертификат. Заголовок при этом не
    /// отправляется — соединение до чужого адреса, о котором никто не просил,
    /// в журнале сервера выглядит чужим трафиком.
    pub async fn verify(&self) -> Result<(), ProtocolError> {
        if let Some(xhttp) = &self.xhttp {
            return Ok(xhttp.verify().await.map_err(TrojanError::from)?);
        }
        let plain = connect::dial(&*self.dialer, &self.host, self.port).await?;
        let _session = self.tls.connect(plain).await.map_err(TrojanError::from)?;
        Ok(())
    }
}

#[async_trait]
impl Outbound for TrojanOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // Ровно то, что стоит в настройках: соврать здесь означает, что
            // DNS-запросы уйдут в направление, которое их молча потеряет.
            udp: self.config.udp,
            // Каждый поток — своё соединение TLS со своим рукопожатием.
            multiplex: false,
            port_hopping: false,
            // Имя уезжает серверу доменом и разрешается на той стороне.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        self.start(CMD_CONNECT, target).await
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        if !self.config.udp {
            return Err(TrojanError::UdpDisabled.into());
        }

        let placeholder = SocketAddress::ip(
            UDP_PLACEHOLDER
                .parse()
                .map_err(|_| TrojanError::config("не разбирается собственная заглушка адреса"))?,
            0,
        );
        let io = self.start(CMD_UDP, &placeholder).await?;
        Ok(Box::new(TrojanDatagram::new(io)))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        // Общее соединение QUIC есть только у `xhttp`.
        if let Some(xhttp) = &self.xhttp {
            xhttp.close().await;
        }
        Ok(())
    }
}
