//! CSTP: тоннель поверх TLS, кадры, keepalive/DPD, направление уровня пакетов.
//!
//! ```text
//!  connect      CONNECT, заголовки X-CSTP-*, разбор ответа сервера
//!  frame        формат кадра: магия, длина, тип
//!  keepalive    чистое решение «что сделать сейчас» по прошедшему времени
//!  connection   PacketOutbound: читающая задача, таймер, запись
//! ```

pub mod connect;
pub mod connection;
pub mod frame;
pub mod keepalive;

pub use connect::Params;
pub use connection::CstpConnection;
