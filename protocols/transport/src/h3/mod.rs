//! HTTP/3 для клиента (RFC 9114) — своя реализация поверх `quinn`.
//!
//! # Зачем своя
//!
//! `h3` 0.0.8 — последний выпуск — шлёт `:scheme` и `:path` в классическом
//! `CONNECT`, хотя RFC 9114, §4.4 их запрещает, и не отдаёт номер потока,
//! без которого датаграммы HTTP/3 (RFC 9297) не к чему привязать. Здесь
//! запрос уходит ровно таким, каким собран ([`message`]), а номер потока
//! и датаграммы — часть интерфейса.
//!
//! # Что есть и чего нет
//!
//! Только клиент. Запросы, ответы, тело, расширенный `CONNECT` (RFC 9220),
//! датаграммы (RFC 9297), `GOAWAY`. Динамической таблицы QPACK нет — ни в
//! одну сторону ([`qpack`]); проталкивания нет — `MAX_PUSH_ID` клиент не
//! шлёт, и сервер проталкивать не вправе.
//!
//! # Сверка
//!
//! Константы сняты с текстов RFC 9114, 9204, 9220, 9297 и RFC 7541; таблицы
//! — разбором текста, со сверкой по `h3` 0.0.8. Внешние векторы — RFC 7541
//! (Хаффман, целые) и RFC 9204, приложение B (блок полей). Против живого
//! сервера не проверялось — это работа `scripts/interop`.
//!
//! ```text
//!  frame, settings, message, datagram, qpack   разбор без сети
//!  connection   соединение: SETTINGS, запросы, датаграммы
//!  control      фоновая задача: потоки сервера и датаграммы
//!  stream       поток запроса: ответ и тело
//!  reader       кадры из потока QUIC
//!  dispatch     датаграммы по запросам
//! ```

pub mod code;
pub mod datagram;
pub mod error;
pub mod frame;
pub mod message;
pub mod qpack;
pub mod settings;

#[cfg(feature = "quic")]
mod connection;
#[cfg(feature = "quic")]
mod control;
#[cfg(feature = "quic")]
mod dispatch;
#[cfg(feature = "quic")]
mod reader;
#[cfg(feature = "quic")]
mod stream;

#[cfg(feature = "quic")]
pub use connection::{Connection, Options};
#[cfg(feature = "quic")]
pub use dispatch::DatagramReceiver;
pub use error::{H3Error, H3Result};
pub use message::{Request, Response};
#[cfg(feature = "quic")]
pub use stream::{RecvStream, RequestStream, SendStream};
