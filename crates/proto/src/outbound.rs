//! `Outbound` — трейт исходящего соединения. Единственное, что клиент знает о протоколе.
//!
//! Вся остальная программа общается с протоколом только через этот трейт.
//! Отсюда следует главное свойство архитектуры: добавление второго протокола
//! не меняет ни `engine`, ни `router`, ни `gui` — там нет ни одной строки,
//! которая знала бы слово «hysteria».

use async_trait::async_trait;
use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;

use crate::capabilities::Capabilities;
use crate::datagram::ProxyDatagram;
use crate::error::ProtocolError;
use crate::stream::ProxyStream;

/// Исходящее направление: умеет открыть поток или датаграммный канал наружу.
///
/// Реализация обязана быть разделяемой: один `Outbound` на профиль
/// обслуживает все соединения сразу. Открывать по QUIC-соединению на каждый
/// TCP-поток — значит платить рукопожатием за каждую вкладку браузера.
#[async_trait]
pub trait Outbound: Send + Sync + 'static {
    /// Идентификатор, под которым это направление известно маршрутизатору.
    fn id(&self) -> OutboundId;

    /// Имя протокола для журнала и интерфейса: `"hysteria2"`, `"direct"`.
    fn protocol(&self) -> &'static str;

    /// Что это направление умеет. Маршрутизатор смотрит сюда, прежде чем
    /// отдать ему UDP-сессию.
    fn capabilities(&self) -> Capabilities;

    /// Открывает поток до `target`.
    ///
    /// `target` может быть доменом: разрешать его — дело той стороны.
    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError>;

    /// Открывает датаграммный канал.
    ///
    /// Адрес назначения указывается на каждой посылке, поэтому один канал
    /// обслуживает всю UDP-сессию приложения.
    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError>;

    /// Закрывает нижележащее соединение и освобождает ресурсы.
    ///
    /// Вызывается при отключении и при смене профиля. Реализация по умолчанию
    /// ничего не делает — протоколам без состояния закрывать нечего.
    async fn close(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}
