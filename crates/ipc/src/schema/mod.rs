//! Схема сообщений — контракт между демоном и интерфейсом, которые обновляются
//! по отдельности: новое поле только необязательное, новый вариант только в
//! конец, удалять и переименовывать нельзя.

pub mod event;
pub mod request;
pub mod response;

pub use event::{Event, LogLevel};
pub use request::Request;
pub use response::{AppInfo, Explanation, ProbeResult, Response, RuleTrace, StatusReport};
