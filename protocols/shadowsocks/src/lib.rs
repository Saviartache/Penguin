//! Shadowsocks: поток, зашифрованный целиком, без заголовков снаружи.
//!
//! Клиент бросает соль, выводит из неё и пароля сеансовый ключ и шлёт всё под ним:
//! сначала адрес назначения, потом данные. Рукопожатия и ответа сервера нет.
//!
//! - Отказа нет: неверный пароль виден как не сошедшаяся метка, `AuthRejected`.
//! - Подтверждения соединения нет: недостижимый адрес выглядит молчанием.
//! - Мультиплексирования нет: соединение, соль и ключ на каждый поток.
//! - Потоковых шифров (`aes-256-cfb`, `rc4-md5`) нет: они не заверяют данные.
//! - Внешних плагинов нет: сокеты выдаёт [`penguin_proto::dialer::Dialer`].
//!
//! ```text
//!  factory ──► outbound ──┬─► stream    AEAD: соль, длина, кусок
//!                         ├─► datagram  AEAD: соль на каждой посылке
//!                         ├─► tcp2022   2022: заголовок с меткой времени
//!                         └─► udp2022   2022: идентификатор сессии, счётчик
//!  crypto — метод AEAD и вывод ключей; method, kdf2022, header2022 — метод 2022
//! ```
//!
//! # AEAD 2022
//!
//! Ключ — base64 PSK нужной длины ([`ShadowsocksConfig::validate`]), подключ — BLAKE3
//! ([`kdf2022`]), заголовки с меткой времени ([`tcp2022`], [`udp2022`]). Метка старше
//! 30 с отвергается ([`header2022::check_timestamp`]), ошибка называет расхождение часов.
//! Раскладка сверена с `shadowsocks-rust` v1.25.0 (`relay/{tcp,udp}relay/aead_2022.rs`,
//! `proxy_stream/protocol/v2.rs`), `shadowsocks-crypto` v0.8.0 и `sing-shadowsocks2`.
//!
//! Упрощено сознательно: нет EIH (один PSK на профиль), окна антиреплея и кеша смены
//! сессии UDP (защита сервера), обновления сессии (в 2022 его нет).
//!
//! # Проверки
//!
//! Подключ BLAKE3 сверен с официальным вектором `derive_key`, блочный AES — с FIPS-197,
//! `XChaCha20-Poly1305` — с `draft-irtf-cfrg-xchacha` A.1. Записанного вектора подключа
//! с меткой 2022 нет; раскладка заголовков проверена круговым прогоном. С живым сервером
//! 2022 не проверялось.

pub mod config;
pub mod crypto;
pub mod datagram;
pub mod error;
pub mod factory;
pub mod header2022;
pub mod kdf2022;
pub mod method;
pub mod outbound;
pub mod stream;
pub mod tcp2022;
pub mod udp2022;

pub use config::ShadowsocksConfig;
pub use crypto::Method;
pub use error::{ShadowsocksError, ShadowsocksResult};
pub use factory::ShadowsocksFactory;
pub use method::{Method2022, ShadowsocksMethod};
pub use outbound::ShadowsocksOutbound;

/// Имя протокола в конфигурации; менять нельзя (стоит в файлах пользователей).
pub const PROTOCOL: &str = "shadowsocks";
