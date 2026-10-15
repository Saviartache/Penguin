//! Как открыть поток до сервера: сокет, TLS, перенос, заголовок.
//!
//! Тот же приём, что и у VLESS: адрес назначения назван в заголовке запроса,
//! значит на каждого адресата нужен свой поток со своим заголовком, и
//! открывать их умеет канал датаграмм, а не только направление. Держать ради
//! этого ссылку на направление значило бы завести цикл — вместо неё оба
//! держат один [`Connector`].

use std::sync::Arc;

use penguin_core::address::{Address, SocketAddress};
use penguin_core::uuid::Uuid;
use penguin_proto::connect;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;
use penguin_transport::tls::TlsClient;
use penguin_transport::xhttp::{XhttpClient, XhttpTarget};
use penguin_transport::{carrier, deadline};
use tokio::io::AsyncWriteExt;

use crate::config::{Security, Transport, VmessConfig};
use crate::crypto::{Session, Wire};
use crate::error::VmessError;
use crate::frame::request;
use crate::stream::VmessStream;

/// Всё, что нужно, чтобы открыть поток до сервера.
pub struct Connector {
    host: Address,
    port: u16,
    uuid: Uuid,
    wire: Wire,
    tls: Option<TlsClient>,
    transport: Transport,
    path: String,
    http_host: String,
    /// Клиент XHTTP — только у `transport = "xhttp"`.
    xhttp: Option<XhttpClient>,
    dialer: Arc<dyn Dialer>,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls.is_some())
            .field("transport", &self.transport)
            .finish()
    }
}

impl Connector {
    /// Собирает соединитель по проверенным настройкам.
    pub fn new(config: &VmessConfig, dialer: Arc<dyn Dialer>) -> Result<Self, ProtocolError> {
        let (host, port) = config.endpoint()?;
        let tls = match config.security {
            Security::Tls => Some(
                TlsClient::new(&config.tls, &host, config.transport.default_alpn())
                    .map_err(VmessError::from)?,
            ),
            Security::None => None,
        };

        let http_host = config.host()?;
        let xhttp = config.transport.is_quic().then(|| {
            let target = XhttpTarget {
                host: host.clone(),
                port,
                tls: config.tls.clone(),
                authority: http_host.clone(),
                path: config.path().to_owned(),
            };
            XhttpClient::new(target, Arc::clone(&dialer))
        });

        Ok(Self {
            host,
            port,
            uuid: config.uuid(),
            wire: config.cipher.wire(),
            tls,
            transport: config.transport,
            path: config.path().to_owned(),
            http_host,
            xhttp,
            dialer: Arc::clone(&dialer),
        })
    }

    /// Закрывает общее соединение QUIC, если оно есть (`xhttp`).
    pub async fn close(&self) {
        if let Some(xhttp) = &self.xhttp {
            xhttp.close().await;
        }
    }

    /// Открывает поток и отправляет заголовок запроса.
    pub async fn open(
        &self,
        command: u8,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let mut io = self.carry().await?;
        let session = Session::new(self.wire);
        let header = request::build(&self.uuid, &session, command, target)?;

        deadline::handshake::<_, VmessError>("заголовок VMess", async {
            io.write_all(&header).await?;
            io.flush().await?;
            Ok(())
        })
        .await?;

        Ok(Box::new(VmessStream::new(io, &session)))
    }

    /// Соединение до сервера вместе с переносом, но без заголовка.
    async fn carry(&self) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        if let Some(xhttp) = &self.xhttp {
            return Ok(Box::new(xhttp.open().await.map_err(VmessError::from)?));
        }
        let plain = connect::dial(&*self.dialer, &self.host, self.port).await?;

        let secure: Box<dyn ProxyStream> = match &self.tls {
            Some(tls) => Box::new(tls.connect(plain).await.map_err(VmessError::from)?),
            None => Box::new(plain),
        };

        Ok(
            carrier::wrap(secure, self.transport, &self.http_host, &self.path)
                .await
                .map_err(VmessError::from)?,
        )
    }

    /// Проверяет, что сервер на месте и предъявляет ожидаемый сертификат.
    ///
    /// UUID здесь не проверяется, и проверить его нечем: сервер, не узнавший
    /// его, закрывает соединение молча. Заголовок при этом не отправляется —
    /// соединение до чужого адреса, о котором никто не просил, в журнале
    /// сервера выглядит чужим трафиком.
    pub async fn verify(&self) -> Result<(), ProtocolError> {
        // Без запроса: только QUIC и сертификат.
        if let Some(xhttp) = &self.xhttp {
            return Ok(xhttp.verify().await.map_err(VmessError::from)?);
        }
        let _carrier = self.carry().await?;
        Ok(())
    }
}
