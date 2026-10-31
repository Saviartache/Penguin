//! Открытие потока до сервера: сокет, TLS, перенос, заголовок.
//!
//! Адрес назван в заголовке, поэтому потоки открывает и [`crate::outbound`], и канал датаграмм;
//! оба держат один [`Connector`].

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

use crate::config::{Security, Transport, VlessConfig};
use crate::error::{VlessError, VlessResult};
use crate::frame::{addons, request};
use crate::reality::{self, RealityConfig};
use crate::stream::VlessStream;
use crate::vision::VisionStream;

/// Всё, что нужно, чтобы открыть поток до сервера.
pub struct Connector {
    host: Address,
    port: u16,
    uuid: Uuid,
    /// `None` — `security` не `"tls"`.
    tls: Option<TlsClient>,
    /// `None` — `security` не `"reality"`.
    reality: Option<RealityConfig>,
    /// Включён `flow = xtls-rprx-vision`.
    vision: bool,
    transport: Transport,
    /// Путь `xhttp` или `serviceName` у `grpc`.
    path: String,
    /// `:authority` для них же.
    http_host: String,
    xhttp: Option<XhttpClient>,
    dialer: Arc<dyn Dialer>,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls.is_some())
            .field("reality", &self.reality.is_some())
            .field("vision", &self.vision)
            .field("transport", &self.transport)
            .finish()
    }
}

impl Connector {
    /// Собирает соединитель по проверенным настройкам.
    pub fn new(config: &VlessConfig, dialer: Arc<dyn Dialer>) -> VlessResult<Self> {
        let (host, port) = config.endpoint()?;
        let (tls, reality) = match config.security {
            Security::Tls => (
                Some(TlsClient::new(
                    &config.tls,
                    &host,
                    config.transport.default_alpn(),
                )?),
                None,
            ),
            Security::None => (None, None),
            Security::Reality => {
                let reality = config.reality.clone().ok_or_else(|| {
                    VlessError::config("`security = \"reality\"` без блока `reality`")
                })?;
                (None, Some(reality))
            }
        };

        let vision = config.flow() == Some(addons::FLOW_VISION);
        let http_host = config.host()?;
        // Поверх Reality XHTTP идёт по HTTP/2 через `carrier::wrap`
        let xhttp = (config.transport.is_quic() && reality.is_none()).then(|| {
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
            uuid: config.uuid,
            tls,
            reality,
            vision,
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
        let flow = self.vision.then_some(addons::FLOW_VISION);
        let header = request::request(&self.uuid, command, target, flow)?;

        deadline::handshake::<_, VlessError>("заголовок VLESS", async {
            io.write_all(&header).await?;
            io.flush().await?;
            Ok(())
        })
        .await?;

        Ok(Box::new(VlessStream::new(io)))
    }

    /// Соединение до сервера вместе с переносом, но без заголовка.
    async fn carry(&self) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        if let Some(xhttp) = &self.xhttp {
            return Ok(Box::new(xhttp.open().await.map_err(VlessError::from)?));
        }
        let plain = connect::dial(&*self.dialer, &self.host, self.port).await?;

        let secure: Box<dyn ProxyStream> = if let Some(tls) = &self.tls {
            Box::new(tls.connect(plain).await.map_err(VlessError::from)?)
        } else if let Some(reality) = &self.reality {
            let stream = deadline::handshake::<_, VlessError>("рукопожатие Reality", async {
                Ok(reality::connect(plain, reality).await?)
            })
            .await?;
            if self.vision {
                Box::new(VisionStream::new(stream, *self.uuid.as_bytes()))
            } else {
                Box::new(stream)
            }
        } else {
            Box::new(plain)
        };

        Ok(
            carrier::wrap(secure, self.transport, &self.http_host, &self.path)
                .await
                .map_err(VlessError::from)?,
        )
    }

    /// Сервер на месте с ожидаемым сертификатом (TLS) или подтверждает себя как Reality
    /// (до HMAC сертификата, дешевле [`Self::open`]). UUID не проверяется, заголовок не шлётся.
    pub async fn verify(&self) -> Result<(), ProtocolError> {
        if let Some(config) = &self.reality {
            let mut plain = connect::dial(&*self.dialer, &self.host, self.port).await?;
            deadline::handshake::<_, VlessError>("рукопожатие Reality", async {
                reality::verify(&mut plain, config).await?;
                Ok(())
            })
            .await?;
            return Ok(());
        }
        if let Some(xhttp) = &self.xhttp {
            return Ok(xhttp.verify().await.map_err(VlessError::from)?);
        }

        let _carrier = self.carry().await?;
        Ok(())
    }
}
