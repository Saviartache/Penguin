//! Канал `direct-tcpip` как [`ProxyStream`](penguin_proto::stream::ProxyStream).
//!
//! `russh` уже даёт канал в виде `AsyncRead + AsyncWrite`
//! ([`russh::ChannelStream`]) — работы здесь ровно столько, чтобы удержать
//! рядом соединение, которому канал принадлежит.
//!
//! # Зачем держать соединение
//!
//! Канал живёт поверх фоновой задачи `russh`, которую держит
//! [`russh::client::Handle`] внутри [`Link`]. Уронить `Link` раньше канала
//! значило бы оборвать поток на середине разговора.
//!
//! # Закрытие
//!
//! `ChannelStream` закрывает канал сам при падении (`Drop`): отдельного кода
//! на это не нужно, `poll_shutdown` просто доводит запись до конца.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use russh::ChannelStream;
use russh::client::Msg;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::session::Link;

/// Поток приложения: канал `direct-tcpip` внутри соединения SSH.
pub struct SshStream {
    /// Соединение. Роняется последним.
    _link: Arc<Link>,
    inner: ChannelStream<Msg>,
}

impl std::fmt::Debug for SshStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshStream").finish()
    }
}

impl SshStream {
    /// Сводит канал и соединение, которому он принадлежит.
    pub fn new(link: Arc<Link>, channel: russh::Channel<Msg>) -> Self {
        Self {
            _link: link,
            inner: channel.into_stream(),
        }
    }
}

impl AsyncRead for SshStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SshStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
