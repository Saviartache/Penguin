//! `Outbound` поверх HTTP/2.
//!
//! Общий код — `CONNECT` и дополнение — вынесен в [`crate::connect`] и
//! [`crate::padding`]; здесь остаётся только то, как открыть соединение и
//! как завести новый поток внутри него.

pub mod h2;

pub use h2::NaiveHttp2Outbound;
