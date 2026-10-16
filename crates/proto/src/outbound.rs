//! `Outbound` — трейт исходящего соединения, единственное, что клиент знает о протоколе.

use async_trait::async_trait;
use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;
use penguin_core::stats::Rtt;

use crate::capabilities::Capabilities;
use crate::datagram::ProxyDatagram;
use crate::error::ProtocolError;
use crate::stream::ProxyStream;

/// Исходящее направление; один `Outbound` на профиль обслуживает все соединения.
#[async_trait]
pub trait Outbound: Send + Sync + 'static {
    /// Идентификатор направления для маршрутизатора.
    fn id(&self) -> OutboundId;

    /// Имя протокола для журнала и интерфейса: `"hysteria2"`, `"direct"`.
    fn protocol(&self) -> &'static str;

    /// Что направление умеет; маршрутизатор смотрит сюда перед UDP-сессией.
    fn capabilities(&self) -> Capabilities;

    /// Открывает поток до `target` (домен разрешает другая сторона).
    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError>;

    /// Открывает датаграммный канал; адрес указывается на каждой посылке.
    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError>;

    /// Собственный замер задержки; `None` — не умеет, тогда меряется открытием потока.
    ///
    /// У мультиплексоров открытие потока ничего не ждёт и показало бы ноль.
    async fn rtt(&self) -> Option<Rtt> {
        None
    }

    /// Живо ли постоянное соединение; мёртвое пул пересоздаёт по профилю.
    ///
    /// Нужно тем, кто держит одно соединение на все потоки: после его смерти
    /// каждый `connect_tcp` отвечал бы ошибкой до переподключения руками.
    fn is_alive(&self) -> bool {
        true
    }

    /// Закрывает нижележащее соединение; по умолчанию ничего не делает.
    async fn close(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}
