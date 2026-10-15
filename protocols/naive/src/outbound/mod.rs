//! `Outbound` для обоих транспортов naive: HTTP/2 и HTTP/3.
//!
//! Общий код — `CONNECT` и дополнение — вынесен в [`crate::connect`] и
//! [`crate::padding`]; здесь остаётся только то, как открыть соединение и
//! как завести новый поток внутри него.

pub mod h2;
pub mod h3;

pub use h2::NaiveHttp2Outbound;
pub use h3::NaiveHttp3Outbound;
