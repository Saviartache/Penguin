//! `PacketOutbound` — направление на IP-пакетах (WireGuard, MASQUE `CONNECT-IP`).
//! В потоки пакеты превращает движок; отдельный трейт нужен, чтобы `connect_tcp` не обещали зря.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::id::OutboundId;
use penguin_core::stats::Rtt;

use crate::error::ProtocolError;

/// Виртуальный интерфейс направления внутри тоннеля; спрашивается после подключения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketInterface {
    /// Адрес IPv4 и длина префикса.
    pub ipv4: (Ipv4Addr, u8),
    /// Адрес IPv6, если сервер его выдал.
    pub ipv6: Option<(Ipv6Addr, u8)>,
    /// Наибольший пакет, который направление берёт целиком (WireGuard: 1420).
    pub mtu: u16,
    /// Серверы имён внутри тоннеля, по предпочтению; пусто — имена не разрешить (мимо тоннеля нельзя).
    pub dns: Vec<IpAddr>,
}

/// Направление на IP-пакетах; одно на профиль, обслуживает весь трафик.
#[async_trait]
pub trait PacketOutbound: Send + Sync + 'static {
    /// Идентификатор направления для маршрутизатора.
    fn id(&self) -> OutboundId;

    /// Имя протокола для журнала и интерфейса: `"wireguard"`.
    fn protocol(&self) -> &'static str;

    /// Каким интерфейсом направление выглядит изнутри.
    fn interface(&self) -> PacketInterface;

    /// Отправляет пакет в тоннель; пакет длиннее [`PacketInterface::mtu`] не обрезается.
    async fn send(&self, packet: &[u8]) -> Result<(), ProtocolError>;

    /// Ждёт следующий пакет из тоннеля.
    async fn recv(&self) -> Result<Bytes, ProtocolError>;

    /// Собственный замер задержки; см. [`Outbound::rtt`](crate::outbound::Outbound::rtt).
    async fn rtt(&self) -> Option<Rtt> {
        None
    }

    /// Живо ли направление; см. [`Outbound::is_alive`](crate::outbound::Outbound::is_alive).
    fn is_alive(&self) -> bool {
        true
    }

    /// Закрывает направление и его фоновые задачи.
    async fn close(&self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

/// Фабрика протокола уровня пакетов, отдельная от [`ProtocolFactory`](crate::factory::ProtocolFactory).
#[async_trait]
pub trait PacketFactory: Send + Sync + 'static {
    /// Имя протокола в конфигурации: `"wireguard"`.
    fn protocol(&self) -> &'static str;

    /// Проверяет параметры, не создавая соединения.
    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError>;

    /// Собирает направление и поднимает тоннель.
    async fn build(
        &self,
        ctx: crate::factory::BuildContext,
        params: &serde_json::Value,
    ) -> Result<std::sync::Arc<dyn PacketOutbound>, ProtocolError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_interface_carries_the_mtu_the_tunnel_really_has() {
        let interface = PacketInterface {
            ipv4: (Ipv4Addr::new(10, 0, 0, 2), 32),
            ipv6: None,
            mtu: 1420,
            dns: Vec::new(),
        };
        assert!(interface.mtu < 1500);
        assert_eq!(interface.clone(), interface);
    }
}
