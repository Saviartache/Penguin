//! `ProxyStream` — двунаправленный поток байт до целевого адреса.

use tokio::io::{AsyncRead, AsyncWrite};

/// Поток до целевого адреса; отдельный трейт нужен для `Box<dyn ProxyStream>`. `Send`, но не `Sync`.
pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
