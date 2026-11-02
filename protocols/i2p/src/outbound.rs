//! Направление через outproxy I2P.
//!
//! Состояния нет, кроме настроек: на каждое соединение — свой поток I2P,
//! поэтому [`Capabilities::multiplex`] = `false`.

use std::sync::Arc;
use std::time::Duration;

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
use tokio::net::TcpStream;

use crate::config::I2pConfig;
use crate::error::{I2pError, I2pResult};
use crate::handshake;

/// Срок шага: поиск набора адресов outproxy в I2P идёт десятки секунд.
const STEP: Duration = Duration::from_secs(60);

/// Исходящее направление через outproxy I2P.
pub struct I2pOutbound {
    id: OutboundId,
    /// Прокси i2pd, разобранный при сборке.
    proxy: (Address, u16),
    /// `имя.b32.i2p:порт` outproxy.
    outproxy: String,
    dialer: Arc<dyn Dialer>,
}

impl I2pOutbound {
    /// Собирает направление, соединений не открывая.
    pub fn new(id: OutboundId, config: &I2pConfig, dialer: Arc<dyn Dialer>) -> I2pResult<Self> {
        Ok(Self {
            id,
            proxy: config.proxy_endpoint()?,
            outproxy: config.outproxy_authority()?,
            dialer,
        })
    }

    /// Соединение с прокси i2pd.
    async fn dial(&self) -> Result<TcpStream, ProtocolError> {
        let (host, port) = &self.proxy;
        connect::dial(&*self.dialer, host, *port)
            .await
            .map_err(|err| {
                ProtocolError::Connect(format!("прокси i2pd на `{host}:{port}` не отвечает: {err}"))
            })
    }

    /// Проверяет, что i2pd на месте; сеть I2P при этом может быть ещё не готова.
    pub async fn verify(&self) -> Result<(), ProtocolError> {
        self.dial().await.map(drop)
    }
}

impl std::fmt::Debug for I2pOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("I2pOutbound")
            .field("id", &self.id)
            .field("outproxy", &self.outproxy)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Outbound for I2pOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            udp: false,
            multiplex: false,
            port_hopping: false,
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let mut io = self.dial().await?;

        let code = deadline::within::<_, I2pError>(STEP, "поток I2P до outproxy", async {
            handshake::connect(&mut io, &self.outproxy).await
        })
        .await?;
        if code != 200 {
            return Err(I2pError::OutproxyUnreachable(code).into());
        }

        let target = target.to_wire();
        let code = deadline::within::<_, I2pError>(STEP, "CONNECT через outproxy", async {
            handshake::connect(&mut io, &target).await
        })
        .await?;
        if code != 200 {
            return Err(I2pError::Refused { target, code }.into());
        }
        Ok(Box::new(io))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        Err(ProtocolError::Unsupported("UDP"))
    }
}
