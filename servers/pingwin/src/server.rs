//! Приём соединений: рукопожатие, сессия, прикрытие.
//!
//! ```text
//!  accept ──► рукопожатие ──┬── свой   ──► сессия ──► relay
//!                           └── чужой  ──► fallback
//! ```

use std::sync::Arc;

use anyhow::{Context, Result};
use penguin_pingwin::handshake::{self, Outcome};
use penguin_pingwin::mux::{Incoming, Role, Session};
use penguin_pingwin::wire::keys::StaticKeyPair;
use tokio::net::{TcpListener, TcpStream};

use crate::config::ServerConfig;
use crate::policy::Policy;
use crate::{fallback, relay};

/// Всё, что нужно каждому соединению.
pub struct Server {
    config: ServerConfig,
    keys: StaticKeyPair,
    policy: Policy,
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
    /// Готовит сервер к работе, ничего не открывая.
    pub fn new(config: ServerConfig) -> Result<Self> {
        let keys = config.keys()?;
        let policy = Policy::new(&config, &keys.public)?;
        Ok(Self {
            config,
            keys,
            policy,
        })
    }

    /// Открытый ключ — тот, что стоит в профиле клиента.
    pub fn public_key(&self) -> String {
        penguin_core::base64::encode(&self.keys.public)
    }

    /// Слушает и обслуживает соединения, пока не попросят остановиться.
    pub async fn run(self: Arc<Self>, shutdown: impl Future<Output = ()>) -> Result<()> {
        let addr = self.config.listen_addr()?;
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("не слушается `{addr}`"))?;

        tracing::info!(
            %addr,
            users = self.policy.len(),
            cover = self.config.fallback_addr().unwrap_or("нет"),
            "сервер pingwin слушает"
        );

        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((socket, peer)) => {
                        let server = Arc::clone(&self);
                        tokio::spawn(async move { server.serve(socket, peer).await });
                    }
                    Err(err) => {
                        // Кончились дескрипторы или сеть исчезла: рвать всё
                        // из-за одного неудачного `accept` нельзя.
                        tracing::warn!(%err, "соединение не принялось");
                    }
                },
                () = &mut shutdown => {
                    tracing::info!("сервер останавливается");
                    return Ok(());
                }
            }
        }
    }

    /// Обслуживает одно соединение.
    async fn serve(&self, mut socket: TcpStream, peer: std::net::SocketAddr) {
        // Мелкие посылки не склеиваются: у мультиплексора запись — это кадр,
        // и задержка в сорок миллисекунд ради экономии заголовка здесь
        // означает задержку каждого ответа.
        let _ = socket.set_nodelay(true);

        // Срок отдаётся рукопожатию, а не ставится вокруг него: истёкшее
        // время — это ещё один способ узнать чужого клиента, и прочитанное к
        // тому моменту должно уйти прикрытию. Обёртка снаружи выбросила бы
        // эти байты вместе с решением.
        let shook = handshake::accept(
            &mut socket,
            &self.keys,
            &self.policy,
            self.config.handshake_limit(),
        )
        .await;

        match shook {
            Ok(Outcome::Ours(accepted)) => {
                let user = self.policy.name(&accepted.user).unwrap_or("?").to_owned();
                tracing::info!(%peer, user, cover = accepted.cover.as_deref().unwrap_or("нет"), "клиент опознан");
                if let Err(err) = self.session(socket, *accepted).await {
                    tracing::debug!(%peer, user, %err, "сессия закрылась");
                }
            }
            Ok(Outcome::Foreign(seen)) => {
                tracing::debug!(%peer, bytes = seen.len(), "клиент не опознан — уходит к прикрытию");
                match self.config.fallback_addr() {
                    Some(cover) => fallback::proxy(socket, seen, cover).await,
                    None => tracing::trace!(%peer, "прикрытия нет — соединение закрыто"),
                }
            }
            // Сюда попадает только молчащее соединение: всё, из чего можно
            // было сделать вывод, рукопожатие вернуло решением, а не ошибкой.
            Err(err) => tracing::debug!(%peer, %err, "рукопожатие не состоялось"),
        }
    }

    /// Ведёт сессию до её конца.
    async fn session(&self, socket: TcpStream, accepted: handshake::Accepted) -> Result<()> {
        let (session, mut incoming) = Session::start(
            Box::new(socket),
            Role::Server,
            &accepted.keys,
            accepted.algorithm,
            accepted.early,
        )?;

        while let Some(request) = incoming.recv().await {
            match request {
                Incoming::Stream(request) => {
                    tokio::spawn(relay::stream(*request));
                }
                Incoming::Datagram(request) => {
                    tokio::spawn(relay::datagram(*request));
                }
            }
        }

        session.close().await;
        Ok(())
    }
}
