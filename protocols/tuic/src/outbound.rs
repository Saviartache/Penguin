//! Направление через сервер TUIC.
//!
//! В отличие от прокси-протоколов, соединение здесь **постоянное**: оно
//! поднимается один раз при сборке направления и живёт, пока живёт профиль.
//! Рукопожатие QUIC и проверка подлинности платятся один раз на всё.
//!
//! Отсюда и поведение при обрыве: заново соединение здесь не поднимается.
//! Оборвалось — `connect_tcp` отвечает `Disconnected`, а поднимать профиль
//! заново — дело `supervisor`, который для этого и существует. Своя попытка
//! переподключиться здесь означала бы вторую лестницу повторов рядом с той,
//! что уже есть, и две разные политики ожидания.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::connect;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;

use crate::config::TuicConfig;
use crate::datagram::TuicDatagram;
use crate::error::{TuicError, TuicResult};
use crate::session::Session;
use crate::stream::TuicStream;
use crate::transport;

/// Исходящее направление через сервер TUIC.
#[derive(Debug)]
pub struct TuicOutbound {
    id: OutboundId,
    /// Пускать ли UDP.
    udp: bool,
    session: Arc<Session>,
}

impl TuicOutbound {
    /// Поднимает соединение и представляется серверу.
    pub async fn connect(
        id: OutboundId,
        config: TuicConfig,
        dialer: Arc<dyn Dialer>,
    ) -> TuicResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;

        // Имя для TLS берётся из настроек, а если его там нет — из адреса
        // сервера. Тот же порядок, что у остальных протоколов.
        let server_name = match config.tls.sni.as_deref().map(str::trim) {
            Some(sni) if !sni.is_empty() => sni.to_owned(),
            _ => host.to_string(),
        };

        let addresses = connect::resolve(&*dialer, &host, port)
            .await
            .map_err(|e| TuicError::Disconnected(e.to_string()))?;

        // Адреса перебираются по порядку: у имени их бывает несколько, и
        // первый может не отвечать — так бывает у сервера с записью IPv6 в
        // сети без IPv6.
        let mut last = None;
        for address in addresses {
            match transport::connect(&config, &*dialer, address, &server_name).await {
                Ok(transport) => {
                    let session = Session::start(transport, &config).await?;
                    return Ok(Self {
                        id,
                        udp: config.udp,
                        session,
                    });
                }
                Err(err) => last = Some(err),
            }
        }

        Err(last.unwrap_or_else(|| {
            TuicError::Disconnected(format!("до `{host}:{port}` не нашлось ни одного адреса"))
        }))
    }
}

#[async_trait]
impl Outbound for TuicOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            udp: self.udp,
            // Соединение одно на профиль: открытие потока внутри него дёшево,
            // и маршрутизатор вправе на это рассчитывать.
            multiplex: true,
            port_hopping: false,
            // Имя уезжает серверу доменом и разрешается на той стороне.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        if !self.session.is_alive() {
            return Err(TuicError::Disconnected("соединение QUIC закрыто".to_owned()).into());
        }
        let (send, recv) = self.session.open(target).await?;
        Ok(Box::new(TuicStream::new(send, recv)))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        if !self.udp {
            return Err(ProtocolError::Unsupported("UDP"));
        }
        if !self.session.is_alive() {
            return Err(TuicError::Disconnected("соединение QUIC закрыто".to_owned()).into());
        }
        Ok(Box::new(TuicDatagram::new(Arc::clone(&self.session))))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.session.close();
        Ok(())
    }
}
