//! Измерение задержки и доступности сервера до подключения.

use std::time::{Duration, Instant};

use penguin_core::address::SocketAddress;
use penguin_core::stats::Rtt;

use crate::error::ProtocolError;
use crate::outbound::Outbound;

/// Куда стучаться, проверяя, жив ли сервер.
///
/// Именно через сам протокол, а не `ping`: ICMP до сервера может ходить
/// прекрасно, пока QUIC на нужном порту режется. Проверка должна мерить то,
/// чем потом пойдёт трафик.
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

/// Мерит время до открытия потока через уже поднятое направление.
///
/// Свободная функция, а не метод трейта: измерение одинаково для всех
/// протоколов, и заставлять каждый повторять его — верный способ получить
/// пять разных способов округления миллисекунд.
pub async fn probe(
    outbound: &dyn Outbound,
    target: &SocketAddress,
    timeout: Duration,
) -> ProbeResult {
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
