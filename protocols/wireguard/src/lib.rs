//! WireGuard: Noise IK поверх UDP, направление уровня пакетов.
//!
//! ## Чем этот протокол отличается от всех остальных в дереве
//!
//! Он реализует [`PacketOutbound`](penguin_proto::packet::PacketOutbound), а
//! не [`Outbound`](penguin_proto::outbound::Outbound): не открывает потоков и
//! не знает слова «соединение», а даёт трубу для IP-пакетов. Превращает
//! пакеты в потоки TCP движок (`penguin-engine` через `penguin-netstack`) —
//! этот крейт про это ничего не знает и знать не должен: `smoltcp` в его
//! зависимостях означал бы, что протокол начал понимать, кто им пользуется.
//!
//! ## Устройство
//!
//! ```text
//!  factory ─► outbound::connect ─► рукопожатие (crypto::handshake)
//!                  │                     │
//!                  │              PendingHandshake ──► сеанс (crypto::session)
//!                  ▼
//!            outbound::driver — один сокет, один сеанс, три таймера:
//!            обновление рукопожатия, keepalive, срок жизни сеанса
//!
//!  frame — разбор и сборка байт трёх видов сообщений, без сети и без ключей
//!  crypto::primitives — HASH, HMAC, KDF1/2/3, MAC, AEAD
//!  crypto::replay — окно защиты от повторов
//!  crypto::tai64n — метка времени рукопожатия
//! ```
//!
//! ## Криптография
//!
//! Рукопожатие — Noise IK с модификатором `psk2` (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`):
//! X25519 и BLAKE2s на рукопожатие, дальше пакеты данных — каждый со своим
//! счётчиком, ChaCha20-Poly1305. Крейт всегда инициатор: роль ответчика не
//! реализована и не нужна — сервером этот клиент не бывает.
//!
//! Рукопожатие обновляется примерно раз в две минуты
//! ([`crypto::constants::REKEY_AFTER_TIME`]) отдельной задачей-таймером — это
//! не переподключение: сеанс сменяется на лету, а открытые через
//! `PacketOutbound` потоки этого не замечают. Задача останавливается в
//! [`PacketOutbound::close`](penguin_proto::packet::PacketOutbound::close)
//! вместе со всем остальным — иначе она пережила
//! бы профиль.
//!
//! ## Источники и что осталось непроверенным
//!
//! Сверено построчно с `wireguard-go` (`device/*.go`, ветка `master` на
//! момент написания) и с `boringtun` (`boringtun/src/noise/*.rs`) — обе
//! реализации официально поддерживаются проектом WireGuard и Cloudflare
//! соответственно. Независимая проверка нескольких констант — отдельно,
//! через `openssl dgst -blake2s256` (см. тесты `crypto::primitives`).
//!
//! Не реализовано и не проверялось намеренно:
//! - **Cookie-протокол** (тип сообщения 3) — защита сервера от перегрузки
//!   поддельными рукопожатиями. Без него клиент не проходит рукопожатие,
//!   пока сервер настолько нагружен, что включил cookie, — деградация, а не
//!   тихая потеря связи (см. [`crypto::constants::MESSAGE_COOKIE_REPLY`]).
//! - **Реальный сервер.** Тесты handshake проверены самодельной парой
//!   клиент/сервер по тем же формулам (`crypto::handshake::tests`) и
//!   независимо посчитанными константами, но не разговором с `wg-quick` или
//!   `sing-box` — это отдельная проверка, вне единичных тестов.

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

/// Имя протокола в конфигурации.
///
/// Стоит в файлах настроек пользователей — менять нельзя.
pub const PROTOCOL: &str = "wireguard";
