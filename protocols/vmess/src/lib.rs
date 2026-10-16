//! VMess: шифрует заголовок и тело сам, поверх любого транспорта.
//!
//! Только AEAD-заголовок: `alterId > 0` отклоняется в [`config::VmessConfig::validate`].
//! Бит `0x10` (заверенная длина) и переносы `ws`/`httpupgrade`/`kcp`/`quic` не
//! поддерживаются; есть `tcp`, `grpc`, `xhttp`.
//!
//! Расхождение часов больше 120 с сервер встречает тем же молчаливым закрытием,
//! что и неверный UUID, поэтому текст [`error::VmessError::Disconnected`] называет обе причины.
//!
//! Формат собран по исходникам `v2fly/v2ray-core`, о живой сервер не проверен;
//! тесты идут на записанных байтах и внешнем векторе KDF ([`crypto::kdf`]).

pub mod config;
pub mod connector;
pub mod crypto;
pub mod datagram;
pub mod error;
pub mod factory;
pub mod frame;
pub mod outbound;
pub mod stream;

pub use config::VmessConfig;
pub use error::{VmessError, VmessResult};
pub use factory::VmessFactory;
pub use outbound::VmessOutbound;

/// Имя протокола в конфигурации; менять нельзя.
pub const PROTOCOL: &str = "vmess";
