//! Канал управления между GUI (права пользователя) и демоном (права системы).
//!
//! TUN, маршруты и брандмауэр требуют администратора, поэтому тоннель держит
//! служба, а окно только просит через этот канал.
//!
//! Схема ([`schema`]) — контракт между отдельно обновляемыми сторонами.
//! Доступ к каналу равен доступу к системе: дескриптор безопасности Windows
//! задан явно (`transport::windows`), на Unix сверяются права каталога и peer-uid.
//!
//! # Готовность службы
//!
//! GUI подключается через [`Client::connect_service`], готовность проверяется
//! [`client::greet_service`] / [`client::answers_service`]: отладочный демон
//! пользователя на Unix не должен сойти за службу. [`Client::connect`],
//! [`client::greet`] и [`client::answers`] сохраняют запасной канал для CLI.

pub mod auth;
pub mod client;
pub mod codec;
#[cfg(unix)]
mod controller;
pub mod error;
mod identity;
mod policy;
pub mod schema;
pub mod server;
pub mod transport;

pub use client::Client;
pub use error::{IpcError, IpcResult};
pub use identity::{authorize_controller, current_user_id};
pub use schema::{Event, Request, Response, StatusReport};
pub use server::{Handler, Server};
