//! `Outbound` для TrustTunnel: `CONNECT` поверх HTTP/2 или HTTP/3.
//!
//! Соединяет [`crate::transport`], [`crate::connect`] и [`crate::udp::session`);
//! держит проверку живости (`PROTOCOL.md`, §8) и правило §9.2: `407` закрывает всю сессию.

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
use crate::transport::Link;
use crate::udp::session::UdpManager;

/// Срок и период `CONNECT _check` (`PROTOCOL.md`, §8.4, §13.3). Бездействие
/// не отслеживается (эталон проверяет по `timeout_ms`): проверка идёт безусловно.
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(7);

/// Почему направление нездорово; отдаётся следующим `connect_tcp`/`bind_udp`.
#[derive(Debug, Clone)]
enum Poison {
    /// `407`: пересоздать сессию (`PROTOCOL.md`, §9.2).
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
    /// Общее с задачей проверки живости.
    link: Arc<Link>,
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
    /// Устанавливает соединение; каждый `connect_tcp` — свой поток `CONNECT` в нём.
    pub async fn connect(
        id: OutboundId,
        config: TrustTunnelConfig,
        dialer: Arc<dyn Dialer>,
    ) -> TrustTunnelResult<Self> {
        config.validate()?;
        let link = Arc::new(Link::connect(&config, dialer.as_ref()).await?);

        let poisoned = Arc::new(StdMutex::new(None));
        let health_task = spawn_health_check(
            Arc::clone(&link),
            (config.username.clone(), config.password.clone()),
            Arc::clone(&poisoned),
        );

        Ok(Self {
            id,
            config,
            dialer,
            link,
            udp: AsyncMutex::new(None),
            poisoned,
            health_task,
        })
    }

    /// Ошибка, если направление уже непригодно.
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

    /// Запоминает `407` как причину; первая причина сохраняется.
    fn note_auth_rejected(&self) {
        let mut guard = self.poisoned.lock().unwrap_or_else(|e| e.into_inner());
        guard.get_or_insert(Poison::AuthRejected);
    }

    async fn open_tcp(&self, target: &SocketAddress) -> TrustTunnelResult<Box<dyn ProxyStream>> {
        self.check_alive()?;

        let wire_target = target.to_wire();
        let open = self
            .link
            .open(&wire_target, self.config.credentials(), false);
        let result = connect::perform(&wire_target, open).await;

        match result {
            Ok(stream) => Ok(stream),
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

        let result = UdpManager::connect(
            &self.link,
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
            udp: true,
            multiplex: true,
            port_hopping: false,
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
        self.link.shutdown().await;
        Ok(())
    }
}

/// Фоновая проверка живости: `CONNECT _check` каждые [`HEALTH_CHECK_TIMEOUT`];
/// останавливается после первого провала.
fn spawn_health_check(
    link: Arc<Link>,
    credentials: (String, String),
    poisoned: Arc<StdMutex<Option<Poison>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(HEALTH_CHECK_TIMEOUT).await;

            let outcome = tokio::time::timeout(
                HEALTH_CHECK_TIMEOUT,
                health_check_once(&link, (&credentials.0, &credentials.1)),
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
async fn health_check_once(link: &Link, credentials: (&str, &str)) -> TrustTunnelResult<()> {
    let (status, _stream) = link
        .open(connect::HEALTH_CHECK_AUTHORITY, credentials, true)
        .await?;

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
