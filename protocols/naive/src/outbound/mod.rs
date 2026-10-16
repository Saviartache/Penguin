//! `Outbound` для обоих транспортов naive: HTTP/2 и HTTP/3.

pub mod h2;
pub mod h3;

pub use h2::NaiveHttp2Outbound;
pub use h3::NaiveHttp3Outbound;
