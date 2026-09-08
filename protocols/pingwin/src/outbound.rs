//! Направление: несколько несущих соединений, потоки внутри них.
//!
//! # Почему несущих несколько, а не одна
//!
//! Одна была бы дешевле: рукопожатие платится один раз, а вкладок в браузере
//! сотня. Но у одного соединения TCP одно окно перегрузки и одна история
//! потерь на всех. Замер на живой линии: несущая, однажды поймавшая потери,
//! оседала на `cwnd` в сто сорок сегментов и держала четверть того, что та же
//! линия давала свежему соединению, — и вытащить её оттуда нечем, пока она
//! жива. Четыре несущих дают четыре независимых окна: беда одной не
//! останавливает остальные.
//!
//! Больше четырёх — уже приметно: сто одинаковых приветствий подряд видно
//! не хуже, чем один странный протокол.
//!
//! # Что происходит с первым потоком
//!
//! Он уезжает **вместе с приветствием**: кадр `OPEN` для него собирается
//! раньше, чем появляется сессия, и едет ранними данными (0-RTT). Отсюда
//! свойство, которого нет ни у одного протокола поверх TLS: до первого байта
//! ответа проходит один оборот, а не три.
//!
//! Умершая несущая здесь не воскрешается: она выбрасывается из списка, а на
//! её месте поднимается новая — на следующем же соединении.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use penguin_core::address::{Address, SocketAddress};
use penguin_core::id::OutboundId;
use penguin_core::stats::Rtt;
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
    /// Живые несущие. Мёртвые выбрасываются при первом же обращении.
    sessions: Mutex<Vec<Arc<Session>>>,
    /// Сколько несущих поднимается прямо сейчас.
    ///
    /// Без этого счётчика сотня соединений, стартовавших разом, увидела бы
    /// пустой список и подняла бы сотню несущих вместо четырёх.
    building: AtomicUsize,
}

/// Сколько несущих держать на профиль.
///
/// Четыре — это четыре независимых окна перегрузки и заметный запас против
/// потерь на одной из них. Пятая уже не окупается: выигрыш падает, а
/// одинаковых приветствий к серверу становится больше, чем бывает у браузера.
const CARRIERS: usize = 4;

/// Со скольких потоков несущая считается занятой.
///
/// Восемь — примерно столько соединений браузер открывает к одному сайту.
/// Меньше — и пул рос бы на ровном месте, платя рукопожатием там, где хватило
/// бы готовой несущей; больше — и вся страница ехала бы через одно окно
/// перегрузки.
const STREAMS_PER_CARRIER: usize = 8;

/// Сколько ждать ответа на замер задержки.
///
/// Не дождались — значит несущая либо мертва, либо так загружена, что цифра
/// всё равно ничего не скажет. Пять секунд — это заведомо больше любой
/// разумной задержки и заметно меньше того, что человек готов ждать, глядя
/// на «Проверить».
const RTT_LIMIT: Duration = Duration::from_secs(5);

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
            sessions: Mutex::new(Vec::new()),
            building: AtomicUsize::new(0),
        })
    }

    /// Наименее загруженная живая несущая; заодно выбрасывает мёртвые.
    async fn pick(&self) -> Option<Arc<Session>> {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|session| !session.is_dead());
        sessions
            .iter()
            .min_by_key(|session| session.stream_count())
            .map(Arc::clone)
    }

    /// Стоит ли поднимать ещё одну несущую.
    ///
    /// Не «пока их меньше четырёх», а «пока имеющиеся заняты». Разница в целом
    /// обороте: вторая вкладка браузера, открытая сразу за первой, должна
    /// уехать по уже поднятой несущей за микросекунды, а не платить своим
    /// рукопожатием. Новая заводится только тогда, когда на самой свободной
    /// уже [`STREAMS_PER_CARRIER`] потоков, — то есть когда нагрузка правда
    /// есть.
    ///
    /// Считаются и те, что сейчас поднимаются: без этого сотня соединений,
    /// стартовавших разом, увидела бы пустой список и подняла бы сотню
    /// несущих.
    async fn wants_more(&self) -> bool {
        let (live, busiest_is_loaded) = {
            let mut sessions = self.sessions.lock().await;
            sessions.retain(|session| !session.is_dead());
            let freest = sessions
                .iter()
                .map(|session| session.stream_count())
                .min()
                .unwrap_or(usize::MAX);
            (sessions.len(), freest >= STREAMS_PER_CARRIER)
        };

        if live + self.building.load(Ordering::Relaxed) >= CARRIERS {
            return false;
        }
        live == 0 || busiest_is_loaded
    }

    /// Поднимает несущую, увозя `first` вместе с приветствием.
    async fn establish(
        &self,
        first: Option<&SocketAddress>,
    ) -> PingwinResult<(Arc<Session>, Option<PingwinStream>)> {
        self.building.fetch_add(1, Ordering::Relaxed);
        let raised = self.raise(first).await;
        self.building.fetch_sub(1, Ordering::Relaxed);

        let (session, stream) = raised?;
        self.sessions.lock().await.push(Arc::clone(&session));
        Ok((session, stream))
    }

    /// Само рукопожатие. Отдельно от [`Self::establish`] затем, чтобы счётчик
    /// строящихся уменьшался при любом исходе, включая ошибку.
    async fn raise(
        &self,
        first: Option<&SocketAddress>,
    ) -> PingwinResult<(Arc<Session>, Option<PingwinStream>)> {
        let early = match (self.config.zero_rtt, first) {
            (true, Some(target)) => Some(Session::early_open(target)?),
            _ => None,
        };
        let early_frames = early.as_ref().map(|(_, frame)| frame.clone());

        let mut tcp = penguin_proto::connect::dial(self.dialer.as_ref(), &self.host, self.port)
            .await
            .map_err(|err| PingwinError::disconnected(err.to_string()))?;

        // Без этого ядро придерживает мелкие посылки, ожидая, что за ними
        // придут ещё (алгоритм Нейгла), а собеседник придерживает
        // подтверждение, ожидая данных в ответ. На разговоре «запрос — ответ»
        // эти два ожидания встречаются и дают сорок миллисекунд простоя на
        // каждом обмене. Мультиплексору такое противопоказано: у него посылка
        // — это кадр, и кадры почти всегда мелкие.
        //
        // Раньше это делалось только при включённом обходе DPI — там `NODELAY`
        // нужен, чтобы куски не склеились, — и потому обычный профиль работал
        // заметно медленнее профиля с обходом. Смешнее ошибки не придумаешь.
        if let Err(err) = tcp.set_nodelay(true) {
            tracing::debug!(%err, "не вышло выключить склейку мелких посылок");
        }

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
        // Номер первого потока занимается до того, как сессию увидит кто-то
        // ещё: кадр `OPEN` для него уже уехал, а очередь ещё не заведена.
        if let Some((sid, _)) = &early {
            session.reserve(*sid);
        }

        tracing::debug!(
            server = %self.config.server,
            zero_rtt = established.early_sent,
            "несущая pingwin поднята"
        );

        let stream = match (early, first) {
            (Some((sid, _)), Some(_)) => Some(session.adopt_early(sid)),
            (None, Some(target)) => Some(session.open_tcp(target).await?),
            _ => None,
        };
        Ok((session, stream))
    }

    /// Несущая для операции, которой первый поток не нужен.
    async fn session(&self) -> PingwinResult<Arc<Session>> {
        if let Some(session) = self.pick().await {
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
        // Пока несущих меньше, чем нужно, каждое новое соединение поднимает
        // ещё одну — и уезжает на ней первым потоком, вместе с приветствием.
        // Так пул набирается ровно тогда, когда нагрузка появилась, и не
        // стоит ни одного лишнего оборота: без пула этот поток всё равно ждал
        // бы рукопожатия.
        if self.wants_more().await {
            let (_, stream) = self.establish(Some(target)).await?;
            let stream = stream.ok_or_else(|| {
                PingwinError::disconnected("несущая поднялась без запрошенного потока")
            })?;
            return Ok(Box::new(stream));
        }

        if let Some(session) = self.pick().await {
            match session.open_tcp(target).await {
                Ok(stream) => return Ok(Box::new(stream)),
                // Несущая умерла между выбором и попыткой — обычное дело
                // после долгого простоя. Поднимаем новую и пробуем ещё раз.
                Err(_) if session.is_dead() => {}
                Err(err) => return Err(err.into()),
            }
        }

        let (_, stream) = self.establish(Some(target)).await?;
        let stream = stream.ok_or_else(|| {
            PingwinError::disconnected("несущая поднялась без запрошенного потока")
        })?;
        Ok(Box::new(stream))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        let session = self.session().await?;
        Ok(Box::new(session.open_udp().await?))
    }

    async fn rtt(&self) -> Option<Rtt> {
        // Открытие потока меряет ноль — оно и не ждёт ничего. Задержку
        // спрашивают у самой несущей: проверка живости ходит туда и обратно,
        // то есть меряет ровно то, что человек и хочет увидеть.
        //
        // Несущей нет — отвечаем `None`, и тогда её померят открытием: у
        // первого потока в него входит рукопожатие, а это честный оборот.
        let session = self.pick().await?;
        let took = session.round_trip(RTT_LIMIT).await?;
        let millis = u32::try_from(took.as_millis()).unwrap_or(u32::MAX);
        Some(Rtt::from_millis(millis))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        let sessions = std::mem::take(&mut *self.sessions.lock().await);
        for session in sessions {
            session.close().await;
        }
        Ok(())
    }
}
