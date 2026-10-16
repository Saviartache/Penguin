//! Перекачка байт между приложением и тоннелем.

use penguin_core::address::SocketAddress;
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional_with_sizes};

/// Размер буфера на одно направление.
const BUFFER: usize = 16 * 1024;

/// Качает в обе стороны, пока не закроются обе половины (полузакрытие законно).
pub(crate) async fn relay<C, R>(client: &mut C, remote: &mut R, target: &SocketAddress)
where
    C: AsyncRead + AsyncWrite + Unpin + ?Sized,
    R: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    match copy_bidirectional_with_sizes(client, remote, BUFFER, BUFFER).await {
        Ok((uploaded, downloaded)) => {
            tracing::debug!(%target, uploaded, downloaded, "соединение закрыто");
        }
        Err(err) => tracing::debug!(%target, %err, "соединение оборвано"),
    }
}
