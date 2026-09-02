//! Платформенные реализации TUN.
//!
//! Реализация выбирается в [`crate::device::open`]; выше по стеку про
//! платформу не знают.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;
