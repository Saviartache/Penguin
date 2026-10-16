//! MASQUE: `CONNECT-UDP` поверх HTTP/3 (RFC 9298) и `CONNECT-IP` (RFC 9484, [`ip`]).
//!
//! Источники: RFC 9298 (§2 шаблон, §3 запрос/ответ, §5 датаграмма), RFC 9297
//! (§2.1 `HTTP/3 DATAGRAM`, §3.2 капсулы, §3.5 капсула `DATAGRAM`), RFC 9220
//! (расширенный `CONNECT`, проверяет [`penguin_transport::h3`]), RFC 9484
//! (§3 шаблон, §4.2—4.5 запрос/ответ, §4.7 согласование адреса, §5—6 датаграмма).
//!
//! Корень крейта — `CONNECT-UDP` ([`penguin_proto::datagram::ProxyDatagram`]);
//! [`ip`] — `CONNECT-IP` ([`penguin_proto::packet::PacketOutbound`], протокол
//! `masque-ip`) со своим транспортом. Общее только [`capsule`].
//!
//! UDP едет кадрами `HTTP/3 DATAGRAM`, если прокси принял `SETTINGS_H3_DATAGRAM`,
//! иначе капсулами ([`flow`]). Прокси без расширенного `CONNECT` — ошибка настроек.
//!
//! ```text
//!  factory ──► outbound ──► session ──┬─► transport (QUIC + HTTP/3)
//!                                     ├─► request (CONNECT-UDP)
//!                                     └─► datagram (адрес → канал) ──► flow ──► capsule
//!  ip::factory ──► ip::outbound ──┬─► ip::connect (TLS + Upgrade или HTTP/3)
//!                                 └─► ip::negotiate ──► ip::capsule ──► capsule
//! ```
//!
//! Формат сверен с RFC; тестовых векторов в них нет, интероп против живого
//! сервера не проверялся (`scripts/interop`). Сокеты выдаёт
//! [`penguin_proto::dialer::Dialer`].

pub mod capsule;
pub mod config;
pub mod datagram;
pub mod error;
pub mod factory;
pub mod flow;
pub mod ip;
pub mod outbound;
pub mod request;
pub mod session;
pub mod transport;

pub use config::MasqueConfig;
pub use error::{MasqueError, MasqueResult};
pub use factory::MasqueFactory;
pub use ip::{MasqueIpFactory, PROTOCOL_MASQUE_IP};
pub use outbound::MasqueOutbound;

/// Имя протокола в конфигурации (менять нельзя).
pub const PROTOCOL_MASQUE: &str = "masque";
