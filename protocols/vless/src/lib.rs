//! VLESS: опознание по UUID, шифрует транспорт.
//!
//! Нет отказа: сервер, не узнавший UUID, закрывает соединение молча. Заголовок ответа приходит
//! с первыми данными, его снимает [`stream`] при первом чтении. `security = none` пускает UUID
//! и адрес по сети открытым текстом.
//!
//! Адрес в заголовке один, поэтому поток обслуживает одного адресата; канал датаграмм держит
//! поток на каждого ([`datagram`]). Порт стоит перед типом, домен — `2`, IPv6 — `3`
//! ([`penguin_transport::addr`]).
//!
//! `security = "reality"` ([`reality`]) даёт двойное шифрование, которое снимает
//! `flow = "xtls-rprx-vision"` ([`vision`]; только Reality и `tcp`). Формула Reality сверена лишь
//! между `Xray-core` и `sing-box`: «подключилось» не значит «сервер узнал».
//!
//! Переносы: `tcp`, `grpc`, `xhttp` ([`penguin_transport::carrier`]).

pub mod config;
pub mod connector;
pub mod datagram;
pub mod error;
pub mod factory;
pub mod frame;
pub mod outbound;
pub mod reality;
pub mod stream;
pub mod vision;

pub use config::{Security, Transport, VlessConfig};
pub use error::{VlessError, VlessResult};
pub use factory::VlessFactory;
pub use outbound::VlessOutbound;

/// Имя протокола в конфигурации; менять нельзя.
pub const PROTOCOL: &str = "vless";
