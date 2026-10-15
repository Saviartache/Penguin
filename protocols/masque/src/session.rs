//! Общее соединение HTTP/3 с прокси MASQUE и открытие каналов `CONNECT-UDP`
//! поверх него.
//!
//! Один [`Session`] — одно рукопожатие QUIC/HTTP/3 на весь профиль
//! (`Outbound` обязан быть разделяемым, см. документацию
//! [`penguin_proto::outbound::Outbound`]). Каждый вызов [`Session::open_flow`]
//! открывает внутри уже поднятого соединения новый поток `CONNECT-UDP` —
//! так же дёшево, как новая вкладка в уже открытом браузере.

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

    /// Открывает новый канал `CONNECT-UDP` до `target`.
    ///
    /// `incoming` — очередь того [`crate::datagram::MasqueDatagram`], что
    /// попросил канал: датаграммы, пришедшие по нему, попадают туда же, куда
    /// и датаграммы от других целей того же направления.
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

    /// Закрывает соединение с прокси.
    ///
    /// Каналы, открытые через [`Self::open_flow`], живут в кэше вызывающего
    /// ([`crate::datagram::MasqueDatagram`]) и закрываются им самим —
    /// закрытие транспорта здесь обрывает и их половины потоков, но не ждёт
    /// этого явно.
    pub async fn close(&self) {
        self.transport.link.close(H3_NO_ERROR, b"").await;
    }
}
