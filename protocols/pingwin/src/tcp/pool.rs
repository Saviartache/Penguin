//! Несколько соединений TCP: потоки делят [`STREAM_LINKS`], датаграммы едут по своему.
//!
//! Потеря пакета в TCP тормозит всё соединение; так она тормозит лишь его долю
//! потоков, а DNS и звонки не стоят в очереди за загрузкой. Умершее соединение
//! поднимается заново при следующем запросе к нему.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use penguin_core::address::SocketAddress;
use penguin_proto::dialer::Dialer;
use tokio::sync::Mutex;

use crate::connection::Target;
use crate::error::PingwinResult;
use crate::stream::PingwinStream;
use crate::tcp::datagram::TcpDatagram;
use crate::tcp::io::{H2Recv, H2Send};
use crate::tcp::session::Session;

/// Сколько соединений делят потоки.
pub(crate) const STREAM_LINKS: usize = 2;

/// Одно соединение пула; мёртвое заменяется под замком.
struct Slot(Mutex<Arc<Session>>);

impl Slot {
    fn new(session: Session) -> Self {
        Self(Mutex::new(Arc::new(session)))
    }

    async fn get(&self, target: &Target, dialer: &dyn Dialer) -> PingwinResult<Arc<Session>> {
        let mut session = self.0.lock().await;
        if !session.is_alive() {
            *session = Arc::new(Session::establish(target, dialer).await?);
        }
        Ok(Arc::clone(&session))
    }

    /// Занятый замок — соединение как раз поднимается: считаем живым.
    fn is_alive(&self) -> bool {
        self.0.try_lock().map_or(true, |session| session.is_alive())
    }
}

/// Соединения HTTP/2 одного профиля.
pub(crate) struct Pool {
    streams: [Slot; STREAM_LINKS],
    datagrams: Slot,
    next: AtomicUsize,
}

impl Pool {
    /// Поднимает все соединения разом: рукопожатия идут параллельно.
    pub(crate) async fn establish(target: &Target, dialer: &dyn Dialer) -> PingwinResult<Self> {
        // В куче: три рукопожатия на стеке переполняют его в отладочной сборке.
        let (first, second, datagrams) = tokio::try_join!(
            Box::pin(Session::establish(target, dialer)),
            Box::pin(Session::establish(target, dialer)),
            Box::pin(Session::establish(target, dialer)),
        )?;
        Ok(Self {
            streams: [Slot::new(first), Slot::new(second)],
            datagrams: Slot::new(datagrams),
            next: AtomicUsize::new(0),
        })
    }

    /// Жив хоть один: остальные поднимутся по запросу. Все умерли — сеть сменилась.
    pub(crate) fn is_alive(&self) -> bool {
        self.slots().any(Slot::is_alive)
    }

    /// Открывает поток на следующем по кругу соединении.
    pub(crate) async fn open_tcp(
        &self,
        target: &SocketAddress,
        link: &Target,
        dialer: &dyn Dialer,
    ) -> PingwinResult<PingwinStream<H2Send, H2Recv>> {
        let index = self.next.fetch_add(1, Ordering::Relaxed) % STREAM_LINKS;
        let session = self.streams[index].get(link, dialer).await?;
        session.open_tcp(target).await
    }

    /// Открывает датаграммный канал на своём соединении.
    pub(crate) async fn open_udp(
        &self,
        link: &Target,
        dialer: &dyn Dialer,
    ) -> PingwinResult<TcpDatagram> {
        self.datagrams.get(link, dialer).await?.open_udp().await
    }

    /// Оборот по соединению датаграмм: на нём нет загрузок, которые бы его раздули.
    pub(crate) fn rtt(&self) -> Option<Duration> {
        self.datagrams.0.try_lock().ok()?.rtt()
    }

    /// Закрывает все соединения.
    pub(crate) async fn close(&self) {
        for slot in self.slots() {
            slot.0.lock().await.close();
        }
    }

    fn slots(&self) -> impl Iterator<Item = &Slot> {
        self.streams.iter().chain(std::iter::once(&self.datagrams))
    }
}
