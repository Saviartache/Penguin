//! Поток, зашифрованный кусками: соль, затем пары «длина+метка», «кусок+метка».
//! Общий кадр Shadowsocks и Snell; вывод ключа у протокола ([`Keying`]).

pub mod algorithm;
pub mod cipher;
pub mod keying;
pub mod stream;

pub use algorithm::{Algorithm, NONCE_LEN, TAG_LEN};
pub use cipher::{Cipher, sealed_len};
pub use keying::Keying;
pub use stream::{ChunkStream, MAX_CHUNK, seal_chunk};
