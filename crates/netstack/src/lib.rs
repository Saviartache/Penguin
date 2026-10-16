//! Пользовательский стек TCP/IP поверх TUN: из пакетов получаются соединения.
//!
//! TCP идёт через smoltcp, UDP — мимо (состояния нет, разбор заголовка дешевле сокета на пару адресов).
//! Весь стек — одна задача: smoltcp не рассчитан на несколько потоков, наружу сокеты не выдаются,
//! общение с движком идёт через очереди.
//!
//! ```text
//!   TUN ──пакеты──► [ устройство ──► smoltcp ──► сокеты ] ──очереди──► движок
//! ```

pub mod config;
pub mod device;
pub mod ip;
pub mod outgoing;
pub mod poll;
pub mod stack;
pub mod tcp;
pub mod udp;

pub use config::StackConfig;
pub use outgoing::{ConnectError, Connector, OutgoingHandles};
pub use stack::{Datagram, StackHandles, spawn};
pub use tcp::{Accepted, TcpConnection, TcpListener};
