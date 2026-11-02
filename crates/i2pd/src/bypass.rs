//! SOCKS5 на `127.0.0.1`, через который i2pd выходит в сеть мимо тоннеля.
//!
//! Пароля i2pd не умеет (`NTCP2Server::UseProxy`, «TODO: support username/password»),
//! поэтому пускается только процесс с `pid` запущенного i2pd: иначе любое
//! приложение машины обходило бы тоннель через этот порт.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use penguin_core::network::Network;
use penguin_inbound::{Inbound, InboundHandler, InboundRequest, Socks5Inbound};
use penguin_process::resolver::FlowOwnerResolver;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use tokio_util::sync::CancellationToken;

use crate::error::{I2pdError, I2pdResult};

/// Кого пускать: `0` — пока никого (процесс ещё не запущен).
#[derive(Debug, Default)]
pub struct Admitted(AtomicU32);

impl Admitted {
    /// Пускать процесс `pid`.
    pub fn set(&self, pid: u32) {
        self.0.store(pid, Ordering::Release);
    }

    /// Пускается ли владелец `pid`.
    pub fn allows(&self, owner: Option<u32>) -> bool {
        let admitted = self.0.load(Ordering::Acquire);
        admitted != 0 && owner == Some(admitted)
    }
}

/// Отдаёт соединения i2pd прямому выходу.
struct Handler {
    direct: Arc<dyn Outbound>,
    owners: Arc<dyn FlowOwnerResolver>,
    admitted: Arc<Admitted>,
}

impl Handler {
    fn check(&self, request: &InboundRequest) -> Result<(), ProtocolError> {
        let owner = self
            .owners
            .owner_of(Network::Tcp, request.source)
            .map(|owner| owner.pid);
        if self.admitted.allows(owner) {
            return Ok(());
        }
        tracing::warn!(source = %request.source, ?owner, "обход тоннеля i2pd: чужой процесс отвергнут");
        Err(ProtocolError::Unsupported(
            "обход тоннеля не для этого процесса",
        ))
    }
}

#[async_trait]
impl InboundHandler for Handler {
    async fn open_tcp(
        &self,
        request: &InboundRequest,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        self.check(request)?;
        self.direct.connect_tcp(&request.target).await
    }

    async fn open_udp(
        &self,
        _request: &InboundRequest,
    ) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        Err(ProtocolError::Unsupported("UDP: SSU2 у i2pd выключен"))
    }
}

/// Поднимает обход на случайном порту; работает до отмены `cancel`.
pub async fn start(
    direct: Arc<dyn Outbound>,
    owners: Arc<dyn FlowOwnerResolver>,
    admitted: Arc<Admitted>,
    cancel: CancellationToken,
) -> I2pdResult<SocketAddr> {
    let handler = Arc::new(Handler {
        direct,
        owners,
        admitted,
    });
    let listen = SocketAddr::from(([127, 0, 0, 1], 0));
    let inbound = Socks5Inbound::bind(listen, handler, None)
        .await
        .map_err(|err| I2pdError::Bypass(err.to_string()))?;
    let addr = inbound
        .local_addr()
        .ok_or_else(|| I2pdError::Bypass("адрес не известен".to_owned()))?;
    tokio::spawn(Box::new(inbound).serve(cancel));
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_started_process_is_admitted() {
        let admitted = Admitted::default();
        assert!(!admitted.allows(Some(42)), "до запуска — никого");
        admitted.set(42);
        assert!(admitted.allows(Some(42)));
        assert!(!admitted.allows(Some(43)));
        assert!(!admitted.allows(None), "владелец не найден — отказ");
    }
}
