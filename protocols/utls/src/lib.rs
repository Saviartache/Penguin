//! Свой сборщик `ClientHello` с отпечатком браузера (аналог uTLS) для Reality,
//! Trojan и VLESS/TLS. Крейт не открывает сокетов: он собирает и разбирает байты.
//!
//! ```text
//!  grease        значения-пустышки RFC 8701
//!  record        заголовки TLS-записи и сообщения рукопожатия
//!  extension     кодировщики расширений ClientHello
//!  key_exchange  пары ключей X25519/P-256 для key_share
//!  client_hello  сборка сообщения: перемешивание, padding
//!  fingerprint   отпечатки chrome, firefox, safari
//!  server_hello  разбор ServerHello
//!  rng           источник случайности
//! ```
//!
//! ```
//! use penguin_core::address::Address;
//! use penguin_utls::Fingerprint;
//!
//! let host = Address::domain("example.com");
//! let session_id = penguin_utls::random_session_id();
//! let (hello, _keys) = Fingerprint::Chrome.build(&host, session_id)?;
//! let _on_the_wire = hello.record_bytes();
//! # Ok::<(), penguin_utls::UtlsError>(())
//! ```

pub(crate) mod client_hello;
pub mod error;
pub mod extension;
pub mod fingerprint;
pub mod grease;
pub mod key_exchange;
pub mod record;
pub mod rng;
pub mod server_hello;

pub use error::{UtlsError, UtlsResult};
pub use fingerprint::{ClientHello, Fingerprint};
pub use key_exchange::KeyExchange;
pub use server_hello::{KeyShare, ServerHello};

/// Случайный `SessionID`, как у браузера без Reality.
pub fn random_session_id() -> [u8; 32] {
    penguin_proto::random::array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_session_ids_do_not_repeat() {
        assert_ne!(random_session_id(), random_session_id());
    }
}
