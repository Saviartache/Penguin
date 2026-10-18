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
//!
//! AmneziaWG — обфускация поверх тех же кадров ([`obfs`]), включается
//! необязательной секцией [`config::WireguardConfig::amnezia`]. Поддержаны
//! v1/v2 (`Jc`/`Jmin`/`Jmax`, `S1`–`S4`, `H1`–`H4`) и 1.5/3 (`I1`–`I5`, защита
//! заголовков, `content_padding_addition`, `random_trailers`), сверенные с
//! `amneziawg-go` (b5928ef); таймеры AWG 3 отклоняются. С живым сервером
//! Amnezia не проверялось.

pub mod config;
pub mod crypto;
pub mod error;
pub mod factory;
pub mod frame;
pub mod obfs;
pub mod outbound;

pub use config::WireguardConfig;
pub use error::{WireguardError, WireguardResult};
pub use factory::WireguardFactory;
pub use outbound::WireguardOutbound;

/// Имя протокола в конфигурации (менять нельзя).
pub const PROTOCOL: &str = "wireguard";
