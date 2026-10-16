//! Перенос gRPC по HTTP/2 — как у Xray (`transport/internet/grpc`).
//!
//! Вызов `Tun`: кусок данных — одно сообщение `Hunk`. `TunMulti` не поддержан.
//! Эталон: Xray-core v26.3.27 (`encoding/stream.proto`, `customSeviceName.go`, `config.go`, `dial.go`).

mod client;
pub mod frame;
pub mod path;
mod stream;

pub use client::{Grpc, connect};
pub use stream::GrpcStream;
