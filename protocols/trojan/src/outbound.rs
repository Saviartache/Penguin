//! Направление через сервер Trojan.
//!
//! Без мультиплексирования: поток на подключение (TLS по `tcp`/`grpc`, поток HTTP/3
//! в общем QUIC по `xhttp`). Настройки TLS и отпечаток пароля готовы заранее.

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

/// Адрес в заголовке `UDP`: настоящий стоит на каждой датаграмме, сервер это поле не читает.
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
    /// Собирает направление, соединений не открывая.
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

    /// Проверяет, что сервер отвечает и сертификат сходится. Пароль проверить нечем, заголовок не шлётся.
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
            udp: self.config.udp,
            multiplex: false,
            port_hopping: false,
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
        if let Some(xhttp) = &self.xhttp {
            xhttp.close().await;
        }
        Ok(())
    }
}
