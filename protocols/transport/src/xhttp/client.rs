//! Клиент XHTTP: одно соединение QUIC на направление, по потоку HTTP/3 на
//! каждое соединение приложения.
//!
//! Соединение поднимается при первом потоке и поднимается заново, когда
//! прежнее умерло; так же держит его и Xray (`XmuxClient`).

use std::sync::Arc;

use penguin_core::address::Address;
use penguin_proto::dialer::Dialer;
use tokio::sync::Mutex;

use super::request::stream_one;
use super::stream::XhttpStream;
use crate::error::{TransportError, TransportResult};
use crate::h3::code::H3_NO_ERROR;
use crate::h3::{Connection, Options};
use crate::quic::{self, QuicLink};
use crate::tls::{self, ALPN_H3, TlsConfig};

/// Куда и как ходить по XHTTP.
#[derive(Debug, Clone)]
pub struct XhttpTarget {
    /// Хост сервера.
    pub host: Address,
    /// Порт сервера.
    pub port: u16,
    /// TLS до сервера; имя для него — `sni` или хост.
    pub tls: TlsConfig,
    /// `:authority` запросов: `host` настроек или имя TLS.
    pub authority: String,
    /// Путь из настроек, как есть: нормализует его [`stream_one`].
    pub path: String,
}

/// Клиент XHTTP по HTTP/3.
pub struct XhttpClient {
    target: XhttpTarget,
    dialer: Arc<dyn Dialer>,
    link: Mutex<Option<Link>>,
}

struct Link {
    quic: QuicLink,
    h3: Connection,
}

impl std::fmt::Debug for XhttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XhttpClient")
            .field("target", &self.target)
            .finish()
    }
}

impl XhttpClient {
    /// Собирает клиента. Соединения пока нет.
    pub fn new(target: XhttpTarget, dialer: Arc<dyn Dialer>) -> Self {
        Self {
            target,
            dialer,
            link: Mutex::new(None),
        }
    }

    /// Открывает поток `stream-one`.
    pub async fn open(&self) -> TransportResult<XhttpStream> {
        let h3 = self.connection().await?;
        let request = stream_one(&self.target.authority, &self.target.path);
        let stream = h3
            .send_request(&request)
            .await
            .map_err(TransportError::from)?;
        Ok(XhttpStream::new(stream))
    }

    /// Поднимает соединение без запроса: сервер на месте, сертификат сходится.
    pub async fn verify(&self) -> TransportResult<()> {
        self.connection().await.map(drop)
    }

    /// Закрывает соединение, если оно есть.
    pub async fn close(&self) {
        if let Some(link) = self.link.lock().await.take() {
            link.quic.close(H3_NO_ERROR, b"").await;
        }
    }

    /// Живое соединение: прежнее или новое.
    async fn connection(&self) -> TransportResult<Connection> {
        let mut link = self.link.lock().await;
        if let Some(alive) = link
            .as_ref()
            .filter(|l| l.quic.connection.close_reason().is_none())
        {
            return Ok(alive.h3.clone());
        }
        let target = &self.target;
        let server_name = tls::server_name(&target.tls, &target.host)?;
        let quic = quic::connect(
            &*self.dialer,
            &target.host,
            target.port,
            &server_name.to_str(),
            &target.tls,
            &[ALPN_H3],
        )
        .await?;
        let h3 = Connection::new(quic.connection.clone(), Options::default())
            .await
            .map_err(TransportError::from)?;
        *link = Some(Link {
            quic,
            h3: h3.clone(),
        });
        Ok(h3)
    }
}
