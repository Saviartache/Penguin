//! Измерение задержки и доступности сервера до подключения.

use std::time::{Duration, Instant};

use penguin_core::address::SocketAddress;
use penguin_core::stats::Rtt;

use crate::error::ProtocolError;
use crate::outbound::Outbound;

/// Цель проверки живости: меряется через сам протокол, а не ICMP.
pub const PROBE_TARGET: &str = "cp.cloudflare.com:80";

/// Результат проверки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// Сервер ответил.
    Alive(Rtt),
    /// Сервер не ответил за отведённое время.
    Timeout,
    /// Сервер отказал: чаще всего неверный пароль.
    Rejected(String),
}

impl ProbeResult {
    /// Задержка, если сервер жив.
    pub fn rtt(&self) -> Option<Rtt> {
        match self {
            Self::Alive(rtt) => Some(*rtt),
            Self::Timeout | Self::Rejected(_) => None,
        }
    }
}

/// Мерит задержку поднятого направления: сначала `Outbound::rtt`, иначе время открытия потока.
pub async fn probe(
    outbound: &dyn Outbound,
    target: &SocketAddress,
    timeout: Duration,
) -> ProbeResult {
    if let Ok(Some(rtt)) = tokio::time::timeout(timeout, outbound.rtt()).await {
        return ProbeResult::Alive(rtt);
    }

    let started = Instant::now();
    match tokio::time::timeout(timeout, outbound.connect_tcp(target)).await {
        Ok(Ok(_stream)) => {
            let elapsed = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
            ProbeResult::Alive(Rtt::from_millis(elapsed))
        }
        Ok(Err(ProtocolError::AuthRejected)) => {
            ProbeResult::Rejected("сервер отклонил аутентификацию".to_owned())
        }
        Ok(Err(err)) => ProbeResult::Rejected(err.to_string()),
        Err(_elapsed) => ProbeResult::Timeout,
    }
}
