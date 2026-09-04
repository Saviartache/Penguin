//! Общая часть адаптеров Linux и macOS.
//!
//! Открывают адаптер обе системы по-своему (`platform::linux`,
//! `platform::macos`), а вот дальше он у обеих — обычный дескриптор: читается,
//! пишется и ждёт готовности тем же реактором, что и сокеты. Эта половина
//! общая и живёт здесь.
//!
//! Ссылками соседи не оформлены намеренно: каждого из них видно только в
//! сборке под свою систему, и ссылка сломала бы документацию другой.
//!
//! Отдельного потока чтения, в отличие от Wintun, не нужно: у дескриптора
//! есть неблокирующий режим, и ожидание достаётся `tokio` даром.

mod frame;

use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;

pub(crate) use frame::Header;

use crate::device::TunDevice;
use crate::error::{TunError, TunResult};

/// Адаптер поверх дескриптора.
pub struct UnixTun {
    fd: AsyncFd<OwnedFd>,
    name: String,
    mtu: u16,
    index: Option<u32>,
    header: Header,
    /// Адаптер закрыт [`TunDevice::close`].
    ///
    /// Дескриптор при этом остаётся открытым до [`Drop`]: закрыть его из-под
    /// ожидающей задачи значит отдать номер дескриптора системе, пока на него
    /// кто-то ещё ссылается.
    closed: AtomicBool,
    /// Будит того, кто ждёт пакет, когда адаптер закрывают.
    shutdown: Notify,
}

impl std::fmt::Debug for UnixTun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixTun")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .field("index", &self.index)
            .finish()
    }
}

impl UnixTun {
    /// Заворачивает готовый дескриптор.
    ///
    /// Адрес, MTU и поднятие интерфейса к этому моменту уже сделаны: они у
    /// каждой системы свои, а дескриптор — общий.
    pub(super) fn new(
        fd: OwnedFd,
        name: String,
        mtu: u16,
        header: Header,
    ) -> std::io::Result<Self> {
        set_nonblocking(&fd)?;
        let index = nix::net::if_::if_nametoindex(name.as_str()).ok();

        Ok(Self {
            fd: AsyncFd::with_interest(fd, Interest::READABLE | Interest::WRITABLE)?,
            name,
            mtu,
            index,
            header,
            closed: AtomicBool::new(false),
            shutdown: Notify::new(),
        })
    }
}

/// Переводит дескриптор в неблокирующий режим.
///
/// Без этого чтение остановило бы весь исполнитель: адаптер молчит ровно
/// столько, сколько молчит сеть.
fn set_nonblocking(fd: &OwnedFd) -> std::io::Result<()> {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};

    let flags = fcntl(fd.as_raw_fd(), FcntlArg::F_GETFL)?;
    let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
    fcntl(fd.as_raw_fd(), FcntlArg::F_SETFL(flags))?;
    Ok(())
}

#[async_trait]
impl TunDevice for UnixTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn index(&self) -> Option<u32> {
        self.index
    }

    async fn recv(&self) -> TunResult<BytesMut> {
        loop {
            if self.closed.load(Ordering::Acquire) {
                return Err(TunError::Closed);
            }

            let mut ready = tokio::select! {
                ready = self.fd.readable() => ready?,
                // Закрытие обязано разбудить ожидающего: иначе задача чтения
                // остаётся висеть до первого пакета, которого уже не будет.
                () = self.shutdown.notified() => return Err(TunError::Closed),
            };

            match ready.try_io(|fd| frame::read(fd.get_ref().as_fd(), self.mtu, self.header)) {
                Ok(result) => return Ok(result?),
                // Готовность оказалась ложной — ждём заново.
                Err(_would_block) => continue,
            }
        }
    }

    async fn send(&self, packet: &[u8]) -> TunResult<()> {
        if packet.len() > usize::from(self.mtu) {
            return Err(TunError::PacketTooLarge {
                size: packet.len(),
                mtu: self.mtu,
            });
        }

        loop {
            if self.closed.load(Ordering::Acquire) {
                return Err(TunError::Closed);
            }

            let mut ready = self.fd.writable().await?;
            match ready.try_io(|fd| frame::write(fd.get_ref().as_fd(), packet, self.header)) {
                Ok(result) => return Ok(result?),
                Err(_would_block) => continue,
            }
        }
    }

    async fn close(&self) -> TunResult<()> {
        self.closed.store(true, Ordering::Release);
        self.shutdown.notify_waiters();
        tracing::info!(name = self.name, "адаптер опущен");
        Ok(())
    }
}
