//! Римская нумерация сетевых профилей виртуального адаптера Windows.

#[cfg(any(windows, test))]
mod naming;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::rename;
