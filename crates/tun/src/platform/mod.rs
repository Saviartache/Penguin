//! Платформенные реализации TUN.
//!
//! Реализация выбирается в [`crate::device::open`]; выше по стеку про
//! платформу не знают.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
// Открывают адаптер Linux и macOS по-своему, а дальше он у обеих — обычный
// дескриптор. Эта половина у них общая.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod unix;
#[cfg(windows)]
pub mod windows;
