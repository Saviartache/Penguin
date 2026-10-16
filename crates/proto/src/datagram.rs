//! `ProxyDatagram` — датаграммный канал с адресом на каждой посылке.

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;

use crate::error::ProtocolError;

/// Датаграммный канал наружу; границы сообщений сохраняются, фрагменты собирает протокол.
#[async_trait]
pub trait ProxyDatagram: Send + Sync + 'static {
    /// Отправляет датаграмму по указанному адресу.
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError>;

    /// Ждёт следующую датаграмму и возвращает её вместе с адресом отправителя.
    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError>;

    /// Закрывает канал.
    async fn close(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}
