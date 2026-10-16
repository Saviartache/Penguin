//! TCP Shadowsocks 2022: заголовок с меткой времени и своя AEAD-раскладка.
//!
//! ```text
//!  header  раскладка заголовков
//!  stream  поток: соль, заголовок, куски данных
//! ```

pub mod header;
pub mod stream;

pub use stream::{MAX_CHUNK, Ss2022Stream};
