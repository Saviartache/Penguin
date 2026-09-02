//! Входящие точки: откуда трафик попадает в клиент. TUN — не единственный способ.
//!
//! Две точки, и они дополняют друг друга:
//!
//! | Точка | Кого ловит | Права | Утечка DNS |
//! |---|---|---|---|
//! | [`socks5`] | приложения, настроенные на прокси | не нужны | невозможна: приходит имя |
//! | [`http`] | то же, но по `CONNECT` | не нужны | невозможна |
//! | TUN (`penguin-netstack`) | весь трафик машины | администратор | решается отдельно |
//!
//! Отсюда полезное свойство: прокси-режим работает там, где TUN недоступен —
//! без прав, без драйвера, на чужой машине, — и именно им проверяется, что
//! протокол реализован верно, до того как в игру вступают адаптеры и маршруты.

pub mod error;
pub mod http;
pub mod inbound;
pub mod socks5;

pub use error::{InboundError, InboundResult};
pub use http::HttpInbound;
pub use inbound::{Inbound, InboundHandler, InboundRequest};
pub use socks5::Socks5Inbound;
pub use socks5::auth::Credentials;
