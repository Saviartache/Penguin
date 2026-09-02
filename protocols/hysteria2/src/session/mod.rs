//! Сессии поверх одного QUIC-соединения.
//!
//! Соединение с сервером одно на весь клиент. Внутри него живут:
//!
//! - [`tcp`] — по потоку QUIC на каждое прикладное TCP-соединение;
//! - [`udp`] — датаграммы QUIC, разобранные по номеру сессии;
//! - [`reassembly`] — сборка датаграмм, не поместившихся в путевой MTU.

pub mod reassembly;
pub mod tcp;
pub mod udp;

pub use reassembly::Reassembler;
pub use tcp::TcpStream;
pub use udp::{UdpManager, UdpSession};
