//! WireGuard: Noise IK поверх UDP, направление уровня пакетов.
//!
//! Реализует [`PacketOutbound`](penguin_proto::packet::PacketOutbound): труба
//! для IP-пакетов, потоки из них собирает движок.
//!
//! ```text
//!  factory ─► outbound::connect ─► crypto::handshake ─► crypto::session
//!                  └► outbound::driver: сокет, сеанс, таймер (обновление, keepalive, срок)
//!  frame - раскладка байт; crypto::{primitives, replay, tai64n}
//! ```
//!
//! `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`; всегда инициатор. Рукопожатие
//! обновляется на лету ([`crypto::constants::REKEY_AFTER_TIME`]). Сверено с
//! `wireguard-go` и `boringtun`; не поддержан cookie-протокол (тип 3), с живым
//! сервером не проверялся.

pub mod config;
pub mod crypto;
pub mod error;
pub mod factory;
pub mod frame;
pub mod outbound;

pub use config::WireguardConfig;
pub use error::{WireguardError, WireguardResult};
pub use factory::WireguardFactory;
pub use outbound::WireguardOutbound;

/// Имя протокола в конфигурации (менять нельзя).
pub const PROTOCOL: &str = "wireguard";
