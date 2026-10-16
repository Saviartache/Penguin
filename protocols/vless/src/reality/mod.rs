//! Reality: VLESS под `ClientHello` настоящего браузера; свои сервер узнаёт по расшифровке `SessionID`.
//!
//! `rustls` не даёт подменить `SessionID` и повторить отпечаток, поэтому `ClientHello` собирает
//! `penguin-utls`, а рукопожатие TLS 1.3 ведёт этот модуль.
//!
//! ```text
//!  config          публичный ключ сервера, short_id, server_name, отпечаток
//!  auth            данные опознания, AuthKey, HMAC-проверка сертификата
//!  cipher_suite    шифры TLS 1.3
//!  key_schedule    RFC 8446 §7.1: от Early Secret до прикладных ключей и Finished
//!  record          шифрование и расшифровка записи
//!  certificate     минимальный X.509 DER
//!  flight          серверный полёт после ServerHello
//!  handshake       verify (до Certificate) и connect (до прикладных ключей)
//!  application     прикладные записи, поверх них байты VLESS
//! ```
//!
//! Не поддержаны `KeyUpdate`, `NewSessionTicket`/PSK. Двойное шифрование снимает
//! [`crate::vision`].
//!
//! `key_schedule` и `record` сверены с RFC 8448, `certificate` — с RFC 8410. Формула самой
//! Reality только прочитана (`Xray-core`, `sing-box`); «канал открылся» не значит «сервер нас
//! узнал» — это видно лишь на живом сервере. Форма `security = "reality"`
//! (`crates/gui/src/forms/protocol/vless.rs`) обязана сказать это вслух.

pub mod application;
pub mod auth;
pub mod certificate;
pub mod cipher_suite;
pub mod config;
pub mod error;
mod flight;
pub mod handshake;
pub mod key_schedule;
pub mod record;

pub use application::RealityStream;
pub use config::RealityConfig;
pub use error::RealityError;
pub use handshake::{Verified, connect, verify};
