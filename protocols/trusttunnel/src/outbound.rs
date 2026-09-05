//! `Outbound` для TrustTunnel: `CONNECT` поверх HTTP/2.
//!
//! Собирает воедино три части: [`crate::transport`] (TCP+TLS+HTTP/2),
//! [`crate::connect`] (сам запрос `CONNECT` и разбор кода ответа) и
//! [`crate::udp::session`] (единый поток `_udp2`). Здесь же живёт проверка
//! живости (`PROTOCOL.md`, §8) и правило из §9.2: код `407` предписывает
//! закрыть **всю** сессию, а не только не удавшийся поток.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use async_trait::async_trait;
use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use crate::config::TrustTunnelConfig;
use crate::connect;
use crate::error::{TrustTunnelError, TrustTunnelResult};
use crate::stream::H2Stream;
use crate::transport::{self, H2SendRequest, Http2Transport};
use crate::udp::session::UdpManager;

/// Срок ожидания ответа на `CONNECT _check` (`PROTOCOL.md`, §8.4, §13.3).
///
/// Спецификация описывает проверку как срабатывающую по бездействию: она
/// нужна, когда «данные не приходили `timeout_ms`». Отслеживать бездействие
/// по каждому из потенциально многих одновременных потоков `CONNECT` —
/// отдельная задача сама по себе, и здесь её нет: вместо этого проверка идёт
/// с тем же периодом, каким задан её собственный срок. Цена — чуть больше
/// служебного трафика, чем у эталона при активном тоннеле; на способность
/// заметить мёртвую сессию это не влияет.
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(7);

/// Почему направление признано нездоровым — причина хранится, чтобы её не
/// потерять к моменту, когда следующий вызов `connect_tcp`/`bind_udp` спросит,
/// что случилось.
#[derive(Debug, Clone)]
enum Poison {
    /// `PROTOCOL.md`, §9.2: `407` предписывает пересоздать сессию целиком.
    AuthRejected,
    /// Проверка живости не прошла или соединение оборвалось иначе.
    Disconnected(String),
}

impl From<Poison> for TrustTunnelError {
    fn from(poison: Poison) -> Self {
        match poison {
            Poison::AuthRejected => Self::AuthRejected { status: 407 },
            Poison::Disconnected(message) => Self::Unhealthy(message),
        }
    }
}

/// Направление через сервер TrustTunnel.
pub struct TrustTunnelOutbound {
    id: OutboundId,
    config: TrustTunnelConfig,
    dialer: Arc<dyn Dialer>,
    transport: Http2Transport,
    udp: AsyncMutex<Option<Arc<UdpManager>>>,
    /// `None` — направление ещё годится к использованию.
    poisoned: Arc<StdMutex<Option<Poison>>>,
    health_task: JoinHandle<()>,
}

impl std::fmt::Debug for TrustTunnelOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustTunnelOutbound")
            .field("id", &self.id)
            .field("config", &self.config)
            .finish()
    }
}

impl TrustTunnelOutbound {
    /// Устанавливает соединение с сервером и держит его открытым.
    ///
    /// Соединение одно на весь профиль: каждый `connect_tcp` открывает свой
    /// поток `CONNECT` внутри него, а не поднимает TLS заново.
    pub async fn connect(
        id: OutboundId,
        config: TrustTunnelConfig,
        dialer: Arc<dyn Dialer>,
    ) -> TrustTunnelResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;
        let transport = transport::connect(&config, dialer.as_ref(), &host, port).await?;

        let poisoned = Arc::new(StdMutex::new(None));
        let health_task = spawn_health_check(
            transport.send_request.clone(),
            (config.username.clone(), config.password.clone()),
            Arc::clone(&poisoned),
        );

        Ok(Self {
            id,
            config,
            dialer,
            transport,
            udp: AsyncMutex::new(None),
            poisoned,
            health_task,
        })
    }

    /// Ошибка направления, если оно уже признано непригодным, — до сети.
    fn check_alive(&self) -> TrustTunnelResult<()> {
        match self
            .poisoned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            Some(poison) => Err(poison.into()),
            None => Ok(()),
        }
    }

    /// Запоминает `407` как причину, по которой направление больше не годится.
    ///
    /// Первая причина остаётся: направление, уже признанное нездоровым,
    /// не переобъясняется следующей ошибкой.
    fn note_auth_rejected(&self) {
        let mut guard = self.poisoned.lock().unwrap_or_else(|e| e.into_inner());
        guard.get_or_insert(Poison::AuthRejected);
    }

    async fn open_tcp(&self, target: &SocketAddress) -> TrustTunnelResult<Box<dyn ProxyStream>> {
        self.check_alive()?;

        let mut send_request = self
            .transport
            .send_request
            .clone()
            .ready()
            .await
            .map_err(|e| TrustTunnelError::disconnected(e.to_string()))?;

        let request = connect::request(target, self.config.credentials())?;
        let (response, send_stream) = send_request
            .send_request(request, false)
            .map_err(|e| TrustTunnelError::transport(format!("запрос CONNECT: {e}")))?;

        let wire_target = target.to_wire();
        let result = connect::perform(&wire_target, async {
            let response = response
                .await
                .map_err(|e| TrustTunnelError::disconnected(e.to_string()))?;
            let status = response.status().as_u16();
            let recv_stream = response.into_body();
            Ok((status, H2Stream::new(send_stream, recv_stream)))
        })
        .await;

        match result {
            Ok(stream) => Ok(Box::new(stream)),
            // Один отклонённый адрес не значит, что вся сессия сгнила —
            // сервер мог просто не достучаться до цели (см. `outcome`
            // в `crate::connect`: не любой отказ — это `AuthRejected`.
            Err(err @ TrustTunnelError::AuthRejected { .. }) => {
                self.note_auth_rejected();
                Err(err)
            }
            Err(err) => Err(err),
        }
    }

    async fn udp_manager(&self) -> TrustTunnelResult<Arc<UdpManager>> {
        self.check_alive()?;

        let mut guard = self.udp.lock().await;
        if let Some(manager) = guard.as_ref() {
            return Ok(Arc::clone(manager));
        }

        let send_request = self.transport.send_request.clone();
        let result = UdpManager::connect(
            send_request,
            self.config.credentials(),
            Arc::clone(&self.dialer),
        )
        .await;

        match result {
            Ok(manager) => {
                *guard = Some(Arc::clone(&manager));
                Ok(manager)
            }
            Err(err @ TrustTunnelError::AuthRejected { .. }) => {
                self.note_auth_rejected();
                Err(err)
            }
            Err(err) => Err(err),
        }
    }
}

#[async_trait]
impl Outbound for TrustTunnelOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // Единственная нога — HTTP/2, но UDP по ней ходит: `_udp2` несёт
            // все датаграммы направления (`PROTOCOL.md`, §6.1).
            udp: true,
            // TLS-рукопожатие с сервером происходит один раз на весь профиль,
            // а каждый `connect_tcp` получает свой поток внутри него.
            multiplex: true,
            port_hopping: false,
            // Доменное имя уходит на сервер в `:authority` дословно (TCP) или
            // разрешается на этой стороне перед отправкой кадра (UDP, у
            // которого в кадре только числовой адрес, — см.
            // `crate::udp::session::resolve_numeric`). Разница не видна
            // снаружи: с точки зрения вызывающего домен работает в обоих
            // случаях.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        self.open_tcp(target).await.map_err(Into::into)
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        let manager = self.udp_manager().await.map_err(ProtocolError::from)?;
        Ok(Box::new(manager.open()))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.health_task.abort();
        if let Some(manager) = self.udp.lock().await.take() {
            manager.shutdown();
        }
        self.transport.shutdown();
        Ok(())
    }
}

/// Заводит фоновую проверку живости: `CONNECT _check` каждые
/// [`HEALTH_CHECK_TIMEOUT`] (см. пояснение у константы).
///
/// Останавливается сама, как только направление один раз признано
/// нездоровым, — дальше проверять нечего: `close()` всё равно оборвёт эту
/// задачу явно, а до того ей незачем крутиться просто так.
fn spawn_health_check(
    send_request: H2SendRequest,
    credentials: (String, String),
    poisoned: Arc<StdMutex<Option<Poison>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(HEALTH_CHECK_TIMEOUT).await;

            let outcome = tokio::time::timeout(
                HEALTH_CHECK_TIMEOUT,
                health_check_once(send_request.clone(), (&credentials.0, &credentials.1)),
            )
            .await;

            let poison = match outcome {
                Ok(Ok(())) => continue,
                Ok(Err(TrustTunnelError::AuthRejected { .. })) => Poison::AuthRejected,
                Ok(Err(err)) => Poison::Disconnected(err.to_string()),
                Err(_elapsed) => {
                    Poison::Disconnected("сервер не ответил на `_check` вовремя".to_owned())
                }
            };

            tracing::debug!(?poison, "проверка живости `_check` не прошла");
            poisoned
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_or_insert(poison);
            return;
        }
    })
}

/// Один обмен `CONNECT _check`.
async fn health_check_once(
    send_request: H2SendRequest,
    credentials: (&str, &str),
) -> TrustTunnelResult<()> {
    let mut send_request = send_request
        .ready()
        .await
        .map_err(|e| TrustTunnelError::disconnected(e.to_string()))?;

    let request = connect::request_pseudo(connect::HEALTH_CHECK_AUTHORITY, credentials)?;
    // `true` — поток закрывается с нашей стороны сразу: проверка живости не
    // несёт тела, а сервер-эталон отвечает и сам закрывает поток немедленно
    // (`lib/src/http_downstream.rs`: `send_ok_response(true)` только для
    // `_check`, у `_udp2`/`_icmp` — `false`).
    let (response, _send_stream) = send_request
        .send_request(request, true)
        .map_err(|e| TrustTunnelError::transport(format!("запрос CONNECT _check: {e}")))?;

    let response = response
        .await
        .map_err(|e| TrustTunnelError::disconnected(e.to_string()))?;
    let status = response.status().as_u16();

    match connect::outcome(status, connect::HEALTH_CHECK_AUTHORITY) {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_poisoning_reason_is_kept() {
        // Направление, уже объяснившее себе, почему оно нездорово, не должно
        // переписывать причину следующей ошибкой — иначе диагностика гоняется
        // за симптомом, а не за первопричиной.
        let poisoned = StdMutex::new(None);
        poisoned.lock().unwrap().get_or_insert(Poison::AuthRejected);
        poisoned
            .lock()
            .unwrap()
            .get_or_insert(Poison::Disconnected("позже".to_owned()));

        assert!(matches!(
            poisoned.lock().unwrap().as_ref(),
            Some(Poison::AuthRejected)
        ));
    }

    #[test]
    fn auth_rejection_survives_the_trip_through_poison() {
        let err: TrustTunnelError = Poison::AuthRejected.into();
        assert!(matches!(
            err,
            TrustTunnelError::AuthRejected { status: 407 }
        ));
    }
}
