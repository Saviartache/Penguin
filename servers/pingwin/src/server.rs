//! Приём соединений QUIC: опознанный идёт в relay, чужой - в cover.

use std::sync::Arc;

use anyhow::{Context, Result};
use penguin_pingwin::wire::keys::StaticKeyPair;

use crate::config::ServerConfig;
use crate::connection;
use crate::policy::Policy;
use crate::tls;

/// Всё, что нужно каждому соединению.
pub struct Server {
    pub(crate) config: ServerConfig,
    pub(crate) keys: StaticKeyPair,
    pub(crate) policy: Policy,
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
        Ok(Self {
            config,
            keys,
            policy,
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

        tracing::info!(
            %addr,
            users = self.policy.len(),
            cover = ?self.config.cover,
            "сервер pingwin слушает"
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
