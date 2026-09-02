//! Платформенные реализации поиска владельца соединения.
//!
//! Каждая делает одно и то же разными средствами: по локальному адресу
//! соединения найти процесс. Выбор реализации — в
//! [`crate::resolver::system_resolver`].

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;
