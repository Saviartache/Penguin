//! Свой сборщик `ClientHello` с отпечатком настоящего браузера — то, что в
//! мире Go делает uTLS (`refraction-networking/utls`), а здесь нет: `rustls`
//! собирает `ClientHello` по-своему, и по набору расширений, их порядку,
//! списку шифров и кривых в нём виден именно он, а не браузер.
//!
//! # Зачем это отдельный крейт
//!
//! Отпечаток нужен не одной Reality. Он же нужен Trojan, VLESS с обычным TLS
//! и Shadowsocks с транспортом TLS — везде, где стандартный отпечаток
//! `rustls` выдаёт, что за клиент на самом деле подключился. Поэтому крейт
//! живёт на уровне протоколов (`AGENTS.md` §1.1.1), а не внутри `vless`.
//!
//! # Чего здесь нет и не будет
//!
//! Крейт не открывает сокетов и не ведёт рукопожатия — он собирает и
//! разбирает байты, и всё. Ни `tokio::net`, ни `std::net` в исходниках нет
//! ни при каких настройках; сокет и дальнейший обмен байтами — дело
//! вызывающего.
//!
//! Reality — это не «TLS с настройками»: клиент подменяет `SessionID` в
//! `ClientHello` зашифрованными данными опознания, а сервер по нему решает,
//! свой это клиент или нет. Само шифрование этих данных, сам разбор
//! `HelloRetryRequest` и сертификата, сама XTLS Vision (разбор записей TLS на
//! лету и отказ от повторного шифрования после первых нескольких) — не
//! задача этого крейта. Здесь для Reality есть только то, без чего её не
//! собрать: место, куда положить готовые 32 байта `SessionID`, а не то, что
//! сборщик выдумает сам.
//!
//! # Что внутри
//!
//! ```text
//!  grease        значения-пустышки RFC 8701 и то, как их выбирает BoringSSL
//!  record        заголовок TLS-записи и заголовок сообщения рукопожатия
//!  extension     кодировщики отдельных расширений ClientHello
//!  key_exchange  настоящая пара ключей X25519/P-256 для key_share
//!  client_hello  сборка сообщения целиком: перемешивание, padding
//!  fingerprint   три отпечатка (chrome, firefox, safari) и точка входа
//!  server_hello  разбор ServerHello: версия, шифр, SessionID, key_share
//! ```
//!
//! # С чего начать
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
//!
//! `_keys` — настоящие пары ключей `key_share`: рукопожатие ими не ведёт
//! этот крейт, но довести его до конца можно, не пересобирая ключи заново.

// Внутренняя сборка сообщения: подробности перемешивания и padding нужны
// только модулям `fingerprint::*`, а не тем, кто пользуется крейтом снаружи —
// снаружи есть `Fingerprint::build`.
pub(crate) mod client_hello;
pub mod error;
pub mod extension;
pub mod fingerprint;
pub mod grease;
pub mod key_exchange;
pub mod record;
pub mod server_hello;

pub use error::{UtlsError, UtlsResult};
pub use fingerprint::{ClientHello, Fingerprint};
pub use key_exchange::KeyExchange;
pub use server_hello::{KeyShare, ServerHello};

use rand::RngCore;

/// Обычный случайный `SessionID` — то, что посылает браузер, когда за
/// `ClientHello` не стоит Reality.
///
/// Reality использует то же поле для зашифрованных данных опознания: своё
/// шифрование она делает сама (следующий шаг фазы 19) и вызывает
/// [`Fingerprint::build`] напрямую с готовыми 32 байтами, минуя эту функцию.
pub fn random_session_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_session_ids_do_not_repeat() {
        assert_ne!(random_session_id(), random_session_id());
    }
}
