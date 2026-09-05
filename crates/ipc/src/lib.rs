//! Протокол общения GUI и демона. Демон работает с правами системы, GUI — с
//! правами пользователя.
//!
//! Разделение не ради красоты. TUN-адаптер, маршруты и брандмауэр требуют
//! прав администратора; запускать с ними интерфейс значило бы дать те же
//! права `iced`, `wgpu` и драйверу видеокарты. Поэтому тоннель держит служба,
//! а окно только просит — через этот канал.
//!
//! ```text
//!   penguin-gui (пользователь) ──запрос──► penguin-daemon (система)
//!                              ◄──ответ──
//!                              ◄─события─
//! ```
//!
//! # Схема — это контракт
//!
//! Демон и интерфейс обновляются по отдельности, и после обновления одного из
//! них по разные стороны канала оказываются разные версии. Отсюда правила в
//! [`schema`]: новое поле только необязательное, новый вариант только в
//! конец, удалять и переименовывать нельзя.
//!
//! # Доступ к каналу — это доступ к системе
//!
//! Всё, что демон делает по запросу, доступно тому, кто до канала дотянулся:
//! выключить kill switch, переписать правила, увести весь трафик машины.
//! Поэтому дескриптор безопасности канала задан явно — см.
//! `transport::windows`. Ссылкой это не оформлено намеренно: модуль есть
//! только в сборке под Windows, и ссылка на него сломала бы документацию
//! остальных систем.
//!
//! # Service Readiness
//!
//! GUI connections must use [`Client::connect_service`]. Service startup probes,
//! including elevated/root probes, must use [`client::greet_service`] or
//! [`client::answers_service`]: a Unix per-user foreground daemon must not be
//! mistaken for the system service. Windows uses the existing named pipe.
//! [`Client::connect`], [`client::greet`] and [`client::answers`] retain Unix
//! foreground fallback for CLI and debugging use.

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
