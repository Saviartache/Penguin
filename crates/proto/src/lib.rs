//! Контракт протокола. Всё, что должен уметь протокол, чтобы стать подключаемым.

pub mod capabilities;
pub mod connect;
pub mod datagram;
pub mod dialer;
pub mod error;
pub mod factory;
pub mod outbound;
pub mod packet;
pub mod probe;
pub mod registry;
pub mod stream;
