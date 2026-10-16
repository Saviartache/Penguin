//! Общая часть адаптеров Linux и macOS: после открытия это неблокирующий дескриптор под реактором `tokio`.

mod frame;

use std::os::fd::{AsFd, OwnedFd};
use std::sync::Mutex;
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
    /// Буфер чтения, общий для пакетов пачки; держится только на время `read`.
    buffer: Mutex<BytesMut>,
    /// Дескриптор остаётся открытым до `Drop`: закрытие из-под ожидающей задачи отдало бы его номер системе.
    closed: AtomicBool,
    /// Будит ожидающего пакет при закрытии.
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
    /// Заворачивает готовый дескриптор; адрес, MTU и подъём интерфейса уже сделаны.
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
            buffer: Mutex::new(BytesMut::new()),
            closed: AtomicBool::new(false),
            shutdown: Notify::new(),
        })
    }

    fn read(&self) -> std::io::Result<BytesMut> {
        let mut buffer = self.buffer.lock().unwrap_or_else(|e| e.into_inner());
        frame::read(
            self.fd.get_ref().as_fd(),
            &mut buffer,
            self.mtu,
            self.header,
        )
    }
}

/// Без неблокирующего режима чтение остановило бы исполнитель.
fn set_nonblocking(fd: &OwnedFd) -> std::io::Result<()> {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};

    let flags = fcntl(fd, FcntlArg::F_GETFL)?;
    let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(flags))?;
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
                () = self.shutdown.notified() => return Err(TunError::Closed),
            };

            if let Ok(result) = ready.try_io(|_| self.read()) {
                return Ok(result?);
            }
        }
    }

    // Чтение мимо реактора безопасно: ложная готовность гасится в `recv` через WouldBlock.
    fn try_recv(&self) -> Option<BytesMut> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        match self.read() {
            Ok(packet) => Some(packet).filter(|packet| !packet.is_empty()),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => None,
            Err(err) => {
                tracing::warn!(%err, "чтение из TUN не удалось");
                None
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
            if let Ok(result) =
                ready.try_io(|fd| frame::write(fd.get_ref().as_fd(), packet, self.header))
            {
                return Ok(result?);
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
