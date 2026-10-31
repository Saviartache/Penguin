//! Общий транспорт протоколов: TLS, HTTP/2, HTTP/3, QUIC, адреса, сроки.
//! Сокетов не открывает: их выдаёт [`penguin_proto::dialer::Dialer`].
//! `quinn` и `h2` подключаются фичами `quic` и `h2`.
//!
//! ```text
//!  addr      адрес назначения: SOCKS5 и v2ray
//!  aead      поток, зашифрованный кусками
//!  deadline  срок на рукопожатие
//!  desync    обход DPI первой посылкой
//!  frag      сборка фрагментированных датаграмм
//!  tls       SNI, ALPN, проверка сервера
//!  varint    целое переменной длины QUIC
//!  browser   заголовки Chrome
//!  carrier   перенос: tcp, grpc, xhttp
//!  h3        HTTP/3 клиента
//!  quic      соединение QUIC (quic)
//!  xhttp     XHTTP по HTTP/3 (quic) и HTTP/2 (h2)
//!  h2        поток HTTP/2 как поток байт (h2)
//!  grpc      gRPC по HTTP/2 (h2)
//! ```

pub mod addr;
pub mod aead;
pub mod browser;
pub mod carrier;
pub mod deadline;
pub mod desync;
pub mod error;
pub mod frag;
#[cfg(feature = "h2")]
pub mod grpc;
#[cfg(feature = "h2")]
pub mod h2;
pub mod h3;
pub mod kdf;
#[cfg(feature = "quic")]
pub mod quic;
pub mod tls;
pub mod varint;
pub mod xhttp;

pub use error::{TransportError, TransportResult};
