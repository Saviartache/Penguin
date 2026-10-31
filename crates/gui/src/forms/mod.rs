//! Черновики форм: что набрали и во что это превращается.
//!
//! Отдельно от экранов: черновик проверяется тестами без виджетов. `to_*`
//! возвращает значение или текст ошибки для показа как есть. Поля формы
//! сервера приносит описание протокола ([`protocol`]).

pub mod addresses;
pub mod check;
pub mod deploy;
pub mod flow;
pub mod link;
pub mod protocol;
pub mod punycode;
pub mod rule;
pub mod server;
