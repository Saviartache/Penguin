//! Перенос XHTTP (бывший SplitHTTP) Xray по HTTP/3.
//!
//! Из режимов Xray здесь один — `stream-one`: поток приложения — один
//! `POST`, тело запроса несёт данные к серверу, тело ответа — обратно.
//! Сервер Xray принимает его в режимах `auto`, `stream-one` и `stream-up`
//! (`hub.go`); сервер, настроенный строго на `packet-up`, ответит `400`.
//!
//! Перенос идёт только по HTTP/3: у Xray это `alpn = ["h3"]` в настройках
//! TLS. Отступ — умолчание Xray (100–1000 байт `X` в `Referer`); сервер со
//! своим `xPaddingBytes` или `xPaddingObfsMode` не примет.
//!
//! ```text
//!  request  запрос stream-one: путь, отступ, заголовки Chrome — без сети
//!  stream   тело туда и обратно; ответ ждёт первое чтение
//!  client   одно соединение QUIC на направление
//! ```

mod client;
mod request;
mod stream;

pub use client::{XhttpClient, XhttpTarget};
pub use request::stream_one;
pub use stream::XhttpStream;
