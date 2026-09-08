//! Направление: одна сессия на профиль, потоки внутри неё.
//!
//! # Почему сессия одна
//!
//! Рукопожатие стоит одного оборота, а вкладок в браузере — сотня. Поднимать
//! соединение на каждую значило бы платить этот оборот сто раз и показать
//! наблюдателю сто одинаковых приветствий подряд — приметы яснее не бывает.
//!
//! # Что происходит с первым потоком
//!
//! Он уезжает **вместе с приветствием**: кадр `OPEN` для него собирается
//! раньше, чем появляется сессия, и едет ранними данными (0-RTT). Отсюда
//! свойство, которого нет ни у одного протокола поверх TLS: до первого байта
//! ответа проходит один оборот, а не три.
//!
//! Сессия, умершая по любой причине, здесь не воскрешается: она пересоздаётся
//! на следующем же соединении. Решать, когда пробовать снова, — дело
//! `supervisor`, а не протокола.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::address::{Address, SocketAddress};
use penguin_core::id::OutboundId;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use penguin_transport::aead::Algorithm;
use penguin_transport::deadline;
use penguin_transport::desync::Desync;
use tokio::sync::Mutex;

use crate::config::PingwinConfig;
use crate::error::{PingwinError, PingwinResult};
use crate::handshake::{self, ClientParams};
use crate::mux::session::{Carrier, Role, Session};
use crate::mux::stream::PingwinStream;

/// Направление Pingwin.
pub struct PingwinOutbound {
    id: OutboundId,
    config: PingwinConfig,
    dialer: Arc<dyn Dialer>,
    /// Разобранные один раз настройки: разбирать их на каждое соединение
    /// значило бы платить за base64 и разбор адреса сотню раз.
    host: Address,
    port: u16,
    server_public: [u8; 32],
    cover: Address,
    algorithm: Algorithm,
    desync: Desync,
    /// Живая сессия. Замок держится на время рукопожатия: без него сотня
    /// разом стартовавших соединений подняла бы сотню сессий.
    session: Mutex<Option<Arc<Session>>>,
}

impl std::fmt::Debug for PingwinOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingwinOutbound")
            .field("id", &self.id)
            .field("server", &self.config.server)
            .finish()
    }
}

impl PingwinOutbound {
    /// Собирает направление. Соединения при этом не открывается: первое
    /// рукопожатие происходит на первом же потоке — вместе с ним.
    pub fn new(
        id: OutboundId,
        config: PingwinConfig,
        dialer: Arc<dyn Dialer>,
    ) -> PingwinResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;
        Ok(Self {
            server_public: config.server_public()?,
            cover: config.cover_name()?,
            algorithm: config.algorithm()?,
            desync: config.desync()?,
            id,
            config,
            dialer,
            host,
            port,
            session: Mutex::new(None),
        })
    }

    /// Живая сессия, если она есть.
    async fn live(&self) -> Option<Arc<Session>> {
        let session = self.session.lock().await;
        session
            .as_ref()
            .filter(|session| !session.is_dead())
            .map(Arc::clone)
    }

    /// Поднимает новую сессию, увозя `first` вместе с приветствием.
    ///
    /// Возвращает сессию и — если `first` был назван — уже открытый поток.
    async fn establish(
        &self,
        first: Option<&SocketAddress>,
    ) -> PingwinResult<(Arc<Session>, Option<PingwinStream>)> {
        let mut slot = self.session.lock().await;

        // Пока ждали замок, сессию мог поднять кто-то другой.
        if let Some(session) = slot.as_ref().filter(|session| !session.is_dead()) {
            let session = Arc::clone(session);
            drop(slot);
            let stream = match first {
                Some(target) => Some(session.open_tcp(target).await?),
                None => None,
            };
            return Ok((session, stream));
        }

        let early = match (self.config.zero_rtt, first) {
            (true, Some(target)) => Some(Session::early_open(target)?),
            _ => None,
        };
        let early_frames = early.as_ref().map(|(_, frame)| frame.clone());

        let mut tcp = penguin_proto::connect::dial(self.dialer.as_ref(), &self.host, self.port)
            .await
            .map_err(|err| PingwinError::disconnected(err.to_string()))?;

        let established = deadline::handshake("рукопожатие pingwin", async {
            handshake::connect(
                &mut tcp,
                &ClientParams {
                    server_public: self.server_public,
                    password: self.config.password.as_bytes(),
                    cover: &self.cover,
                    fingerprint: self.config.fingerprint,
                    algorithm: self.algorithm,
                    desync: &self.desync,
                    early: early_frames.as_deref().unwrap_or_default(),
                },
            )
            .await
        })
        .await?;

        let carrier: Carrier = Box::new(tcp);
        let (session, _incoming) = Session::start(
            carrier,
            Role::Client,
            &established.keys,
            established.algorithm,
            None,
        )?;
        // Номер первого потока занимается **до** того, как сессию увидит
        // кто-то ещё: соседнее соединение, дождавшееся замка, иначе взяло бы
        // тот же номер — кадр `OPEN` для него уже уехал, а очередь ещё не
        // заведена.
        if let Some((sid, _)) = &early {
            session.reserve(*sid);
        }
        *slot = Some(Arc::clone(&session));
        drop(slot);

        tracing::debug!(
            server = %self.config.server,
            zero_rtt = established.early_sent,
            "сессия pingwin поднята"
        );

        let stream = match (early, first) {
            (Some((sid, _)), Some(target)) => Some(session.adopt_early(sid, target).await?),
            (None, Some(target)) => Some(session.open_tcp(target).await?),
            _ => None,
        };
        Ok((session, stream))
    }

    /// Сессия для операции, которой первый поток не нужен.
    async fn session(&self) -> PingwinResult<Arc<Session>> {
        if let Some(session) = self.live().await {
            return Ok(session);
        }
        Ok(self.establish(None).await?.0)
    }
}

#[async_trait]
impl Outbound for PingwinOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            udp: true,
            multiplex: true,
            // Смены порта нет: соединение одно и живёт долго, а смена порта
            // имеет смысл там, где соединений много и каждое короткое.
            port_hopping: false,
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        if let Some(session) = self.live().await {
            match session.open_tcp(target).await {
                Ok(stream) => return Ok(Box::new(stream)),
                // Сессия умерла между проверкой и попыткой — обычное дело
                // после долгого простоя. Поднимаем новую и пробуем ещё раз;
                // если и она не поднялась, ошибка уедет наверх как есть.
                Err(_) if session.is_dead() => {}
                Err(err) => return Err(err.into()),
            }
        }

        let (_, stream) = self.establish(Some(target)).await?;
        let stream = stream.ok_or_else(|| {
            PingwinError::disconnected("сессия поднялась без запрошенного потока")
        })?;
        Ok(Box::new(stream))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        let session = self.session().await?;
        Ok(Box::new(session.open_udp().await?))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        let session = self.session.lock().await.take();
        if let Some(session) = session {
            session.close().await;
        }
        Ok(())
    }
}
