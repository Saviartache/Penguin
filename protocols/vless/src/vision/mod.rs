//! XTLS Vision (`flow = "xtls-rprx-vision"`) поверх Reality: конверт набивки на первых пакетах,
//! досмотр внутреннего TLS и, при TLS 1.3 с приемлемым шифром, отказ от второго слоя шифрования.
//!
//! Нужен доступ к записям внешнего TLS, поэтому только `security = "reality"` и `transport = "tcp"`
//! ([`crate::config::VlessConfig::validate`]). Сверено с `XTLS/Xray-core`: `proxy/proxy.go`,
//! `proxy/vless/encoding/`. О живой сервер не проверено.
//!
//! ```text
//!  state    досмотр внутреннего TLS (XtlsFilterTls)
//!  padding  конверт набивки одного блока
//!  stream   VisionStream<S> поверх RealityStream
//! ```

pub mod padding;
pub mod state;
pub mod stream;

pub use stream::VisionStream;
