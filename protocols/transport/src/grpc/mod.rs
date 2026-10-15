//! Перенос gRPC по HTTP/2 — как у Xray (`transport/internet/grpc`).
//!
//! Поток — вызов `Tun` (двунаправленный поток сообщений `Hunk`): каждый
//! кусок данных — одно сообщение gRPC, внутри — `Hunk { bytes data = 1 }`.
//! Режим `TunMulti` (`multiMode`) не поддержан: сервер Xray принимает оба
//! вызова, и обычного хватает.
//!
//! Сверено по исходникам Xray-core `v26.3.27`: `encoding/stream.proto`,
//! `encoding/customSeviceName.go`, `config.go`, `dial.go`.
//!
//! ```text
//!  frame   кадр gRPC и Hunk — без сети
//!  path    путь запроса из serviceName
//!  stream  поток байт поверх сообщений
//!  client  рукопожатие HTTP/2 и запрос
//! ```

mod client;
pub mod frame;
pub mod path;
mod stream;

pub use client::{Grpc, connect};
pub use stream::GrpcStream;
