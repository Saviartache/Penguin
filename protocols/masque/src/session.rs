//! Общее соединение HTTP/3 с прокси MASQUE: одно рукопожатие на профиль,
//! каждый [`Session::open_flow`] — новый поток `CONNECT-UDP` в нём.

use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::dialer::Dialer;
use penguin_transport::h3::code::H3_NO_ERROR;
use tokio::sync::mpsc;

use crate::config::MasqueConfig;
use crate::error::{MasqueError, MasqueResult};
use crate::flow::Flow;
use crate::request;
use crate::transport::{self, Http3Transport};

/// Соединение с прокси MASQUE, разделяемое всеми каналами `CONNECT-UDP`
/// одного направления.
pub struct Session {
    transport: Http3Transport,
    authority: http::uri::Authority,
    authorization: Option<String>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("authority", &self.authority)
            .finish()
    }
}

impl Session {
    /// Устанавливает соединение с прокси и держит его открытым.
    pub async fn connect(config: &MasqueConfig, dialer: &dyn Dialer) -> MasqueResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;
        let server_name = config.server_name()?;

        let authority_text = SocketAddress::new(host.clone(), port).to_wire();
        let authority = http::uri::Authority::try_from(authority_text.as_str())
            .map_err(|e| MasqueError::config(format!("адрес прокси `{authority_text}`: {e}")))?;

        let transport = transport::connect(config, dialer, &host, port, &server_name).await?;
        Ok(Self {
            transport,
            authority,
            authorization: config.authorization.clone(),
        })
    }

    /// Открывает канал `CONNECT-UDP` до `target`; `incoming` — общая очередь входящих.
    pub async fn open_flow(
        &self,
        target: &SocketAddress,
        incoming: mpsc::Sender<(Bytes, SocketAddress)>,
    ) -> MasqueResult<Flow> {
        let request = request::request(&self.authority, target, self.authorization.as_deref());
        let h3 = &self.transport.h3;
        let stream = request::perform(target, h3, &request).await?;
        Ok(Flow::new(target.clone(), stream, h3.clone(), incoming))
    }

    /// Закрывает соединение с прокси (каналы обрываются вместе с ним).
    pub async fn close(&self) {
        self.transport.link.close(H3_NO_ERROR, b"").await;
    }
}
