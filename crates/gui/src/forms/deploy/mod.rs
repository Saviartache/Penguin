//! Развёртывание сервера Pingwin по SSH: что набрано в окне ([`form`]), ход
//! работы `penguin deploy pingwin --json` ([`progress`]) и окно целиком
//! ([`dialog`]).

pub mod dialog;
pub mod form;
pub mod progress;

pub use dialog::Deploy;
pub use form::Field;
pub use progress::{Event, Mark, Progress};
