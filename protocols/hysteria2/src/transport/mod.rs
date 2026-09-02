//! Транспорт: QUIC, смена порта, обфускация.
//!
//! Слои снизу вверх:
//!
//! ```text
//! quinn ──► [socket] ──► [obfs] ──► [hop] ──► сеть
//!             │            │          └─ подмена порта назначения
//!             │            └─ Salamander, Gecko
//!             └─ реализация AsyncUdpSocket для quinn
//! ```
//!
//! Когда ни обфускации, ни смены порта нет, [`socket`] в игру не вступает
//! вовсе: quinn получает обычный сокет и пользуется аппаратной сегментацией.
//! Это заметная разница в скорости, и терять её на пустом месте незачем.

pub mod hop;
pub mod obfs;
pub mod quic;
pub mod socket;

pub use hop::PortHopper;
pub use obfs::Obfuscator;
pub use quic::QuicTransport;
pub use socket::HysteriaSocket;
