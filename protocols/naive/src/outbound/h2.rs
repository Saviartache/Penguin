//! Направление через сервер naive поверх HTTP/2.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;

use crate::config::NaiveConfig;
use crate::connect;
use crate::error::{NaiveError, NaiveResult};
use crate::padding::{self, PaddedStream};
use crate::stream::h2::H2Stream;
use crate::transport::h2::{self as transport, Http2Transport};

/// Направление через сервер naive поверх HTTP/2.
pub struct NaiveHttp2Outbound {
    id: OutboundId,
    config: NaiveConfig,
    transport: Http2Transport,
}

impl std::fmt::Debug for NaiveHttp2Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NaiveHttp2Outbound")
            .field("id", &self.id)
            .field("config", &self.config)
            .finish()
    }
}

impl NaiveHttp2Outbound {
    /// Устанавливает соединение с сервером и держит его открытым.
    ///
    /// Соединение одно на весь профиль: каждый `connect_tcp` открывает свой
    /// поток `CONNECT` внутри него, а не поднимает TLS заново.
    pub async fn connect(
        id: OutboundId,
        config: NaiveConfig,
        dialer: Arc<dyn Dialer>,
    ) -> NaiveResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;
        let transport = transport::connect(&config, dialer.as_ref(), &host, port).await?;
        Ok(Self {
            id,
            config,
            transport,
        })
    }

    async fn open(&self, target: &SocketAddress) -> NaiveResult<Box<dyn ProxyStream>> {
        let mut send_request = self
            .transport
            .send_request
            .clone()
            .ready()
            .await
            .map_err(|e| NaiveError::Disconnected(e.to_string()))?;

        let request = connect::request(target, self.config.credentials())?;
        let (response, send_stream) = send_request
            .send_request(request, false)
            .map_err(|e| NaiveError::transport(format!("запрос CONNECT не отправлен: {e}")))?;

        let stream = connect::perform(target, async {
            let response = response
                .await
                .map_err(|e| NaiveError::Disconnected(e.to_string()))?;
            let status = response.status().as_u16();
            // Тип дополнения решается по ответу на этот конкретный CONNECT —
            // не по соединению целиком: так делает и эталон, см.
            // `crate::padding`.
            let mode = padding::negotiate(response.headers());
            let recv_stream = response.into_body();
            let io = PaddedStream::new(H2Stream::new(send_stream, recv_stream), mode);
            Ok((status, io))
        })
        .await?;

        Ok(Box::new(stream))
    }
}

#[async_trait]
impl Outbound for NaiveHttp2Outbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL_HTTP2
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // У CONNECT нет датаграмм ни в каком виде: соврать здесь значит
            // отправить DNS-запрос в направление, которое его молча потеряет
            // (см. `plan.md`, фаза 12).
            udp: false,
            // Несколько потоков CONNECT делят одно соединение HTTP/2:
            // TLS-рукопожатие платится один раз на весь профиль.
            multiplex: true,
            port_hopping: false,
            // Имя уезжает на сервер в `:authority` и разрешается там.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        self.open(target).await.map_err(Into::into)
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        // Не «выключено настройкой», а «такого не бывает»: маршрутизатор
        // спрашивает возможности заранее и сюда с UDP не приходит, но если
        // придёт — ответ обязан быть честным.
        Err(ProtocolError::Unsupported("UDP"))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        // Без этого задача, качающая кадры соединения, пережила бы само
        // направление: `tokio::spawn` не останавливает задачу сам, когда её
        // `JoinHandle` роняют.
        self.transport.shutdown();
        Ok(())
    }
}
