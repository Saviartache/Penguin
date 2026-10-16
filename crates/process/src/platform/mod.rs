//! Платформенные поиски владельца; выбор — в [`crate::resolver::system_resolver`].

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;
