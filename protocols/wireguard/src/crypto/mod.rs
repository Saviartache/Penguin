//! Криптография WireGuard: примитивы, рукопожатие Noise IK, сеанс данных.
//!
//! Разбор и сборка байт живут в `crate::frame` — здесь только то, что не
//! зависит от формата сообщения на проводе.

pub mod constants;
pub mod handshake;
pub mod primitives;
pub mod replay;
pub mod session;
pub mod tai64n;
