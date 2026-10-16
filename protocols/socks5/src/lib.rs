//! SOCKS5: прокси общего назначения (RFC 1928, RFC 1929).
//!
//! Клиент открывает TCP до прокси, договаривается о проверке подлинности, называет
//! адрес назначения, и дальше идут байты приложения как есть. Шифрования нет: это выход
//! через свой прокси (`ssh -D`, соседний контейнер), не через враждебную сеть.
//!
//! - `socks5-tls` заворачивает в TLS только управляющее соединение и TCP. Датаграммы
//!   `UDP ASSOCIATE` идут открытым текстом, включая DNS; окно говорит об этом у переключателя UDP.
//! - Мультиплексирования нет: [`Socks5Outbound`] помнит только настройки.
//! - UDP отдельным каналом ([`frame::udp`]); управляющее TCP должно жить, пока жив канал.
//! - Имя назначения уходит доменом (`ATYP = 3`), разрешает его прокси.
//!
//! ```text
//!  factory ──► outbound ──┬─► handshake  приветствие, пароль, команда
//!                         └─► datagram   UDP поверх выданного канала
//! ```

pub mod config;
pub mod datagram;
pub mod error;
pub mod factory;
pub mod frame;
pub mod handshake;
pub mod outbound;

pub use config::Socks5Config;
pub use error::{Socks5Error, Socks5Result};
pub use factory::Socks5Factory;
pub use outbound::Socks5Outbound;

/// Имя протокола в конфигурации; менять нельзя (стоит в файлах пользователей).
pub const PROTOCOL: &str = "socks5";

/// То же, но разговор с прокси идёт внутри TLS.
///
/// Отдельное имя, как `http`/`https`: «пароль и адрес видны по дороге» выбирают при добавлении сервера.
pub const PROTOCOL_TLS: &str = "socks5-tls";
