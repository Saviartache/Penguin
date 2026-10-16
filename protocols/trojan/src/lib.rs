//! Trojan: поток внутри TLS, неотличимый от обращения к обычному сайту.
//!
//! Клиент открывает TLS, шлёт 56 байт hex(SHA-224(пароль)), адрес назначения, и дальше
//! идут данные приложения. Шифрует только TLS. Сервер, не узнавший отпечаток, пересылает
//! байты настоящему сайту.
//!
//! - Неверный пароль не отличить от верного: `AuthRejected` взять неоткуда, проверка при
//!   подъёме доходит до сертификата.
//! - Успех соединения с адресом не сообщается: недостижимый адрес выглядит как молчание.
//! - Мультиплексирования нет: `multiplex = false`, на каждый поток своё рукопожатие TLS.
//! - ALPN `h2, http/1.1` — часть маскировки, иной выдал бы клиента до пароля.
//! - UDP идёт внутри того же потока: адрес и длина на каждой посылке ([`frame::udp`]).
//!
//! ```text
//!  factory ──► outbound ──┬─► frame::request  отпечаток, команда, адрес
//!                         └─► datagram        UDP поверх того же потока
//! ```

pub mod config;
pub mod datagram;
pub mod error;
pub mod factory;
pub mod frame;
pub mod outbound;

pub use config::{Transport, TrojanConfig};
pub use error::{TrojanError, TrojanResult};
pub use factory::TrojanFactory;
pub use outbound::TrojanOutbound;

/// Имя протокола в конфигурации; менять нельзя (стоит в файлах пользователей).
pub const PROTOCOL: &str = "trojan";
