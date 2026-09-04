//! Направление через прокси HTTP CONNECT.
//!
//! Состояния между вызовами не держит: мультиплексирования у `CONNECT` нет, и
//! каждое подключение — это своё соединение до прокси со своим запросом.
//! Единственное, что собрано заранее, — настройки TLS: разбирать сертификаты
//! и строить провайдер на каждое открытие вкладки было бы заметно.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::address::{Address, SocketAddress};
use penguin_core::id::OutboundId;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::connect as dial;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use penguin_transport::tls::{ALPN_HTTP11, TlsClient};

use crate::config::HttpProxyConfig;
use crate::connect;
use crate::error::HttpProxyError;
use crate::stream::Prefixed;
use crate::{PROTOCOL_HTTP, PROTOCOL_HTTPS};

/// Исходящее направление через прокси HTTP CONNECT.
pub struct HttpProxyOutbound {
    id: OutboundId,
    config: HttpProxyConfig,
    /// Хост прокси, разобранный один раз при сборке.
    host: Address,
    /// Порт прокси.
    port: u16,
    /// Собранный слой TLS. `None` — протокол `http`, разговор в открытую.
    tls: Option<TlsClient>,
    dialer: Arc<dyn Dialer>,
}

impl std::fmt::Debug for HttpProxyOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpProxyOutbound")
            .field("id", &self.id)
            .field("config", &self.config)
            .field("tls", &self.tls.is_some())
            .finish()
    }
}

impl HttpProxyOutbound {
    /// Собирает направление.
    ///
    /// `secure` — оборачивать ли разговор с прокси в TLS. Соединения при этом
    /// не открывается: подключается направление на каждый поток заново.
    pub fn new(
        id: OutboundId,
        config: HttpProxyConfig,
        secure: bool,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Self, HttpProxyError> {
        config.validate(secure)?;
        let (host, port) = config.endpoint()?;

        let tls = if secure {
            // ALPN — `http/1.1` и только он: `CONNECT` — это HTTP/1.1, и
            // прокси, придирчивый к ALPN, от обещания HTTP/2 сломается.
            Some(TlsClient::new(&config.tls, &host, &[ALPN_HTTP11])?)
        } else {
            None
        };

        Ok(Self {
            id,
            config,
            host,
            port,
            tls,
            dialer,
        })
    }

    /// Открывает поток до целевого адреса через прокси.
    ///
    /// Ветка на TLS одна на весь крейт и стоит здесь: два `CONNECT` — по
    /// одному на каждый вид соединения — разошлись бы при первой же правке.
    async fn open(&self, target: &SocketAddress) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let io = dial::dial(&*self.dialer, &self.host, self.port).await?;
        let credentials = self.config.credentials();

        match &self.tls {
            Some(tls) => {
                let mut io = tls.connect(io).await?;
                let tail = connect::perform(&mut io, target, credentials).await?;
                Ok(Box::new(Prefixed::new(io, tail)))
            }
            None => {
                let mut io = io;
                let tail = connect::perform(&mut io, target, credentials).await?;
                Ok(Box::new(Prefixed::new(io, tail)))
            }
        }
    }

    /// Проверяет, что прокси на месте.
    ///
    /// Зовётся при подъёме направления. `CONNECT` при этом не отправляется:
    /// пробный тоннель до чужого адреса — это соединение, о котором никто не
    /// просил, и в журнале прокси оно выглядит как чужой трафик. Проверяется
    /// то, что можно проверить, никого не беспокоя: отвечает ли прокси и
    /// сходится ли его сертификат.
    pub async fn verify(&self) -> Result<(), ProtocolError> {
        let io = dial::dial(&*self.dialer, &self.host, self.port).await?;
        if let Some(tls) = &self.tls {
            let _session = tls.connect(io).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Outbound for HttpProxyOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        if self.tls.is_some() {
            PROTOCOL_HTTPS
        } else {
            PROTOCOL_HTTP
        }
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // У `CONNECT` датаграмм нет вовсе — ни в каком виде. Соврать здесь
            // означает, что DNS-запросы уйдут в направление, которое их молча
            // потеряет.
            udp: false,
            multiplex: false,
            port_hopping: false,
            // Имя уезжает прокси в строке запроса и разрешается на той стороне.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        self.open(target).await
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        // Не «выключено настройкой», а «такого не бывает»: маршрутизатор
        // спрашивает возможности заранее и сюда с UDP не приходит, но если
        // придёт — ответ обязан быть честным.
        Err(ProtocolError::Unsupported("UDP"))
    }
}
