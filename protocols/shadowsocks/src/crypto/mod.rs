//! Криптография протокола: метод и вывод ключей. Кадр AEAD общий с Snell: [`penguin_transport::aead`].
//!
//! ```text
//!  method  шифр и длина ключа
//!  kdf     пароль -> главный ключ -> сеансовый ключ
//! ```

pub mod kdf;
pub mod method;

pub use method::Method;
pub use penguin_transport::aead::{Cipher, sealed_len};
