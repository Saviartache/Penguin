//! Соединение с сервером: HTTP/3 по QUIC или HTTP/2 по TCP; в `auto` — кто первый.
//!
//! Последний победитель идёт первым, второй стартует с отставанием [`HEAD_START`]:
//! где QUIC режут, повторное подключение не ждёт его зря.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use penguin_core::address::{Address, SocketAddress};
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::stream::ProxyStream;
use penguin_transport::tls::TlsConfig;

use crate::config::Transport;
use crate::error::{PingwinError, PingwinResult};
use crate::session::Session;
use crate::tcp;
use crate::wire::keys::PUBLIC_LEN;

/// Фора первого переноса: столько ждать, прежде чем пробовать второй.
const HEAD_START: Duration = Duration::from_millis(800);

/// Всё, что нужно, чтобы поднять соединение.
pub(crate) struct Target {
    pub(crate) host: Address,
    pub(crate) port: u16,
    pub(crate) server_name: String,
    pub(crate) tls: TlsConfig,
    pub(crate) server_public: [u8; PUBLIC_LEN],
    pub(crate) password: Vec<u8>,
    pub(crate) transport: Transport,
}

/// Опознанное соединение.
pub(crate) enum Connection {
    Quic(Session),
    Tcp(tcp::pool::Pool),
}

impl Connection {
    /// Поднимает соединение; `prefer_tcp` — в `auto` прошлый раз победил TCP (обновляется).
    pub(crate) async fn establish(
        target: &Target,
        dialer: &dyn Dialer,
        prefer_tcp: &AtomicBool,
    ) -> PingwinResult<Self> {
        let quic = Box::pin(async { Session::establish(target, dialer).await.map(Self::Quic) });
        let tcp = Box::pin(async {
            tcp::pool::Pool::establish(target, dialer)
                .await
                .map(Self::Tcp)
        });
        let connection = match target.transport {
            Transport::Quic => quic.await?,
            Transport::Tcp => tcp.await?,
            Transport::Auto if prefer_tcp.load(Ordering::Relaxed) => race(tcp, quic).await?,
            Transport::Auto => race(quic, tcp).await?,
        };
        prefer_tcp.store(matches!(connection, Self::Tcp(_)), Ordering::Relaxed);
        Ok(connection)
    }

    /// Каким переносом поднято (для журнала).
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Quic(_) => "quic",
            Self::Tcp(_) => "tcp",
        }
    }

    /// Соединение живо.
    pub(crate) fn is_alive(&self) -> bool {
        match self {
            Self::Quic(session) => session.is_alive(),
            Self::Tcp(session) => session.is_alive(),
        }
    }

    /// Открывает поток до `target`, не дожидаясь ответа сервера.
    /// `link` и `dialer` — чтобы поднять заново умершее соединение пула TCP.
    pub(crate) async fn open_tcp(
        &self,
        target: &SocketAddress,
        link: &Target,
        dialer: &dyn Dialer,
    ) -> PingwinResult<Box<dyn ProxyStream>> {
        Ok(match self {
            Self::Quic(session) => Box::new(session.open_tcp(target).await?),
            Self::Tcp(pool) => Box::new(pool.open_tcp(target, link, dialer).await?),
        })
    }

    /// Открывает датаграммный канал.
    pub(crate) async fn open_udp(
        &self,
        link: &Target,
        dialer: &dyn Dialer,
    ) -> PingwinResult<Box<dyn ProxyDatagram>> {
        Ok(match self {
            Self::Quic(session) => Box::new(session.open_udp().await?),
            Self::Tcp(pool) => Box::new(pool.open_udp(link, dialer).await?),
        })
    }

    /// Оборот: оценка QUIC или последний пинг HTTP/2.
    pub(crate) fn rtt(&self) -> Option<Duration> {
        match self {
            Self::Quic(session) => Some(session.rtt()),
            Self::Tcp(session) => session.rtt(),
        }
    }

    /// Закрывает соединение штатно.
    pub(crate) async fn close(&self) {
        match self {
            Self::Quic(session) => session.close().await,
            Self::Tcp(pool) => pool.close().await,
        }
    }
}

/// Отказ, который второй перенос не исправит.
fn is_final(err: &PingwinError) -> bool {
    matches!(err, PingwinError::Rejected | PingwinError::Config(_))
}

/// `first` сразу, `second` с отставанием; первое поднявшееся побеждает.
async fn race<T>(
    first: impl Future<Output = PingwinResult<T>>,
    second: impl Future<Output = PingwinResult<T>>,
) -> PingwinResult<T> {
    let second = async {
        tokio::time::sleep(HEAD_START).await;
        second.await
    };
    tokio::pin!(first, second);
    tokio::select! {
        biased;
        done = &mut first => match done {
            Err(err) if !is_final(&err) => {
                tracing::debug!(%err, "первый перенос не поднялся, жду второй");
                second.await
            }
            done => done,
        },
        done = &mut second => match done {
            Err(err) if !is_final(&err) => {
                tracing::debug!(%err, "второй перенос не поднялся, жду первый");
                first.await
            }
            done => done,
        },
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::Instant;

    use super::*;

    fn lost() -> PingwinError {
        PingwinError::disconnected("UDP режут")
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_wins_when_it_is_quick() {
        let won = race(async { Ok(1) }, async { Ok(2) })
            .await
            .expect("поднялось");
        assert_eq!(won, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_first_loses_to_the_second_after_the_head_start() {
        let started = Instant::now();
        let won = race(std::future::pending(), async { Ok(2) })
            .await
            .expect("поднялось");
        assert_eq!(won, 2);
        assert!(started.elapsed() >= HEAD_START);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_first_hands_over_to_the_second() {
        let won = race(async { Err(lost()) }, async { Ok(2) })
            .await
            .expect("поднялось");
        assert_eq!(won, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_rejection_is_not_retried_over_the_other_transport() {
        let err = race::<u8>(
            async { Err(PingwinError::Rejected) },
            std::future::pending(),
        )
        .await
        .expect_err("отказ");
        assert!(matches!(err, PingwinError::Rejected));
    }

    #[tokio::test(start_paused = true)]
    async fn both_failing_is_an_error() {
        let failed = race::<u8>(async { Err(lost()) }, async { Err(lost()) }).await;
        assert!(failed.is_err());
    }
}
