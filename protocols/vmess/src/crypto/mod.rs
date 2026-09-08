//! Криптография VMess: вложенный KDF, опознаватель заголовка, шифр тела.
//!
//! ```text
//!  kdf         вложенный HMAC-SHA256 — "VMess AEAD KDF"
//!  checksum    CRC32 и FNV-1a голыми — без внешней зависимости
//!  auth_id     опознаватель заголовка: время, случайность, CRC32, AES-ECB
//!  aes_gcm     AES-128-GCM заголовка — фиксированный, не зависит от шифра тела
//!  security    какой шифр тела выбран и что из этого едет на провод
//!  id          `cmdKey` и вывод UUID из произвольного текста
//! ```
//!
//! Ничего из этого не относится к формату кадра — он в [`crate::frame`].
//! Здесь только примитивы, из которых кадр собирается.

pub mod aes_gcm;
pub mod auth_id;
pub mod checksum;
pub mod id;
pub mod kdf;
pub mod security;
pub mod session;

pub use security::{Cipher, Wire};
pub use session::Session;
