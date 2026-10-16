//! `CONNECT-IP` (RFC 9484): труба для целых IP-пакетов, одна на профиль
//! ([`penguin_proto::packet::PacketOutbound`]).
//!
//! Только HTTP/3 (`:protocol: connect-ip`, §4.4—4.5); пакеты едут капсулами
//! `DATAGRAM` по потоку, датаграммы не объявляются. После открытия клиент шлёт
//! `ADDRESS_REQUEST` (§4.7.2) и ждёт `ADDRESS_ASSIGN` (§4.7.1); без адреса
//! IPv4 — ошибка. `ROUTE_ADVERTISEMENT` (§4.7.3) только пишется в журнал.
//!
//! MTU — floor 1280 из §7.2 (`outbound::INTERFACE_MTU`): сервер его не
//! сообщает. DNS в интерфейсе всегда пуст: RFC способа не даёт.

mod capsule;
mod connect;
mod factory;
mod negotiate;
mod outbound;
mod request;

pub use factory::MasqueIpFactory;
pub use outbound::MasqueIpOutbound;

/// Имя протокола в конфигурации (менять нельзя).
pub const PROTOCOL_MASQUE_IP: &str = "masque-ip";
