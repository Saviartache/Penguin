//! Приём соединений: QUIC по UDP и TLS по TCP на одном адресе. Опознанный идёт в relay, чужой - в cover.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use penguin_pingwin::wire::keys::StaticKeyPair;
use tokio::net::TcpListener;

use crate::config::ServerConfig;
use crate::policy::Policy;
use crate::{connection, tcp, tls};

/// Пауза после сбоя `accept` (кончились дескрипторы): не крутить цикл вхолостую.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Всё, что нужно каждому соединению.
pub struct Server {
    pub(crate) config: ServerConfig,
    pub(crate) keys: StaticKeyPair,
    pub(crate) policy: Policy,
    pub(crate) tcp: tokio_rustls::TlsAcceptor,
    quic: quinn::ServerConfig,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("listen", &self.config.listen)
            .field("users", &self.policy.len())
            .finish()
    }
}

impl Server {
    /// Готовит сервер к работе: читает ключ и сертификат, сокетов не открывает.
    pub fn new(config: ServerConfig) -> Result<Self> {
        let keys = config.keys()?;
        let policy = Policy::new(&config, &keys.public)?;
        let quic = tls::server_config(&config)?;
        let tcp = tls::tcp_acceptor(&config)?;
        Ok(Self {
            config,
            keys,
            policy,
            tcp,
            quic,
        })
    }

    /// Открытый ключ — тот, что стоит в профиле клиента.
    pub fn public_key(&self) -> String {
        penguin_core::base64::encode(&self.keys.public)
    }

    /// Слушает и обслуживает соединения, пока не попросят остановиться.
    pub async fn run(self: Arc<Self>, shutdown: impl Future<Output = ()>) -> Result<()> {
        let addr = self.config.listen_addr()?;
        let endpoint = quinn::Endpoint::server(self.quic.clone(), addr)
            .with_context(|| format!("не слушается UDP `{addr}`"))?;
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("не слушается TCP `{addr}`"))?;

        tracing::info!(
            %addr,
            users = self.policy.len(),
            cover = ?self.config.cover,
            "сервер pingwin слушает UDP и TCP"
        );

        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            tokio::select! {
                incoming = endpoint.accept() => match incoming {
                    Some(incoming) => {
                        tokio::spawn(connection::serve(Arc::clone(&self), incoming));
                    }
                    None => return Ok(()),
                },
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        tokio::spawn(tcp::connection::serve(Arc::clone(&self), stream, peer));
                    }
                    Err(err) => {
                        tracing::warn!(%err, "TCP не принял соединение");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                    }
                },
                () = &mut shutdown => {
                    tracing::info!("сервер останавливается");
                    endpoint.close(0u32.into(), b"");
                    endpoint.wait_idle().await;
                    return Ok(());
                }
            }
        }
    }
}
