//! Именованный канал с явным дескриптором безопасности.
//!
//! Демон работает с правами системы, и всё доступное через канал доступно тому,
//! кто до него дотянулся; умолчание Windows для канала щедрее нужного.

// Win32-вызовы для SDDL и атрибутов канала; безопасного API в tokio нет.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows::Win32::Foundation::{FALSE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::core::PCWSTR;

use crate::error::{IpcError, IpcResult};

/// SY и BA — всё, IU (вошедший пользователь) — только чтение и запись.
const CHANNEL_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// `ERROR_PIPE_BUSY`: все экземпляры канала заняты.
const PIPE_BUSY: i32 = 231;

/// Сколько клиент ждёт свободного экземпляра канала.
const BUSY_WAIT: Duration = Duration::from_secs(2);

/// Дескриптор безопасности, выделенный системой.
struct Descriptor(PSECURITY_DESCRIPTOR);

// SAFETY: после создания дескриптор только читается.
unsafe impl Send for Descriptor {}
// SAFETY: см. выше.
unsafe impl Sync for Descriptor {}

impl Descriptor {
    fn new(sddl: &str) -> IpcResult<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut raw = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` оканчивается нулём и живёт до конца вызова.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut raw,
                None,
            )
        }
        .map_err(|e| IpcError::Transport(format!("дескриптор безопасности: {e}")))?;
        Ok(Self(raw))
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: память выделена системой в `new` и больше не используется.
        unsafe { LocalFree(HLOCAL(self.0.0)) };
    }
}

/// Принимающая сторона: следующий свободный экземпляр канала.
pub struct Listener {
    path: String,
    descriptor: Descriptor,
    next: NamedPipeServer,
}

impl Listener {
    /// Занимает имя канала; `AlreadyRunning`, если оно уже занято.
    pub(crate) fn bind(name: &str) -> IpcResult<Self> {
        let path = pipe_path(name);
        let descriptor = Descriptor::new(CHANNEL_SDDL)?;
        let next = instance(&path, &descriptor, true).map_err(|e| match e.kind() {
            // Чужой канал с тем же именем даёт «отказано в доступе», а не «занято».
            io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied => IpcError::AlreadyRunning,
            _ => IpcError::Transport(format!("не удалось открыть канал управления: {e}")),
        })?;
        Ok(Self {
            path,
            descriptor,
            next,
        })
    }

    /// Ждёт клиента и подставляет новый свободный экземпляр; сломанный заменяется и при ошибке.
    pub async fn accept(&mut self) -> io::Result<Stream> {
        let connected = self.next.connect().await;
        let next = instance(&self.path, &self.descriptor, false)?;
        let current = std::mem::replace(&mut self.next, next);
        connected.map(|()| Stream::Server(current))
    }
}

fn pipe_path(name: &str) -> String {
    format!(r"\\.\pipe\{name}")
}

fn instance(path: &str, descriptor: &Descriptor, first: bool) -> io::Result<NamedPipeServer> {
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: FALSE,
    };
    // SAFETY: атрибуты и дескриптор живут до конца вызова.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(path, (&raw mut attributes).cast::<c_void>())
    }
}

/// Открывает канал клиентом, пережидая занятость экземпляров не дольше [`BUSY_WAIT`].
pub(crate) async fn connect_to(name: &str) -> io::Result<Stream> {
    let path = pipe_path(name);
    let deadline = tokio::time::Instant::now() + BUSY_WAIT;
    loop {
        match ClientOptions::new().open(&path) {
            Err(e)
                if e.raw_os_error() == Some(PIPE_BUSY)
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            other => return other.map(Stream::Client),
        }
    }
}

/// Соединение с любой из сторон канала.
pub enum Stream {
    /// Принятое сервером.
    Server(NamedPipeServer),
    /// Открытое клиентом.
    Client(NamedPipeClient),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Server(s) => Pin::new(s).poll_read(cx, buf),
            Self::Client(c) => Pin::new(c).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Server(s) => Pin::new(s).poll_write(cx, data),
            Self::Client(c) => Pin::new(c).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Server(s) => Pin::new(s).poll_flush(cx),
            Self::Client(c) => Pin::new(c).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Server(s) => Pin::new(s).poll_shutdown(cx),
            Self::Client(c) => Pin::new(c).poll_shutdown(cx),
        }
    }
}

/// Открывает канал на приём.
pub fn listen() -> IpcResult<Listener> {
    Listener::bind(super::CHANNEL_NAME)
}

/// Подключается к службе.
pub async fn connect_service() -> IpcResult<Stream> {
    super::connect().await
}

pub(super) async fn connect() -> IpcResult<Stream> {
    connect_to(super::CHANNEL_NAME)
        .await
        .map_err(super::classify)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_is_accepted_by_windows() {
        Descriptor::new(CHANNEL_SDDL).expect("дескриптор разбирается");
    }

    #[test]
    fn descriptor_grants_the_interactive_user_only_read_write() {
        assert!(CHANNEL_SDDL.contains("(A;;GRGW;;;IU)"));
        assert!(
            !CHANNEL_SDDL.contains("(A;;GA;;;IU)"),
            "пользователю дан полный доступ"
        );
    }

    #[test]
    fn descriptor_grants_system_and_admins_full_access() {
        assert!(CHANNEL_SDDL.contains("(A;;GA;;;SY)"));
        assert!(CHANNEL_SDDL.contains("(A;;GA;;;BA)"));
    }

    #[test]
    fn descriptor_does_not_grant_everyone() {
        assert!(!CHANNEL_SDDL.contains(";;WD)"), "доступ открыт всем");
    }

    #[tokio::test]
    async fn listen_and_connect_meet() {
        let name = format!("penguin-transport-test-{}", std::process::id());
        let mut listener = Listener::bind(&name).unwrap();
        assert!(matches!(
            Listener::bind(&name),
            Err(IpcError::AlreadyRunning)
        ));
        let (connected, accepted) = tokio::join!(connect_to(&name), listener.accept());
        assert!(connected.is_ok());
        assert!(accepted.is_ok());
    }
}
