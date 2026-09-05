//! Три отпечатка браузера и общая сборка `ClientHello` вокруг них.
//!
//! ```text
//!  chrome    Chrome 120, BoringSSL: GREASE, перемешивание, padding
//!  firefox   Firefox 120, NSS: ни GREASE, ни перемешивания, ни padding
//!  safari    Safari 16.0, BoringSSL: GREASE и padding есть, перемешивания нет
//! ```
//!
//! Каждый модуль отдаёт список шифров, список расширений (уже закодированных
//! в байты, см. [`crate::extension`]) и пары ключей для `key_share` —
//! настоящие, а не для вида (см. [`crate::key_exchange`]). Собирает их в одно
//! сообщение `client_hello::assemble` (внутренняя сборка, не публичный API),
//! зная только два флага на отпечаток: перемешивать ли порядок и добавлять
//! ли `padding`.

pub mod chrome;
pub mod firefox;
pub mod safari;

use std::str::FromStr;

use penguin_core::address::Address;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::client_hello;
use crate::error::{UtlsError, UtlsResult};
use crate::key_exchange::KeyExchange;
use crate::record;

/// Отпечаток браузера, по которому собирается `ClientHello`.
///
/// Версии зафиксированы намеренно (`AGENTS.md`, задача фазы 19): отпечаток
/// Chrome 120 и отпечаток Chrome 131 — разные наборы байт, и «просто chrome»
/// не значит ничего. Подробности и сверка — в документе каждого модуля.
///
/// `Serialize`/`Deserialize` даны сразу, а не только `FromStr`: отпечаток —
/// поле настроек не только у Reality (`penguin-vless`), а у любого протокола,
/// которому однажды понадобится этот крейт (см. `lib.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fingerprint {
    /// Chrome 120 (ноябрь 2023).
    Chrome,
    /// Firefox 120 (ноябрь 2023).
    Firefox,
    /// Safari 16.0 (сентябрь 2022).
    Safari,
}

impl Fingerprint {
    /// Перемешивает ли отпечаток порядок расширений на каждом соединении.
    fn shuffles_extensions(self) -> bool {
        matches!(self, Self::Chrome)
    }

    /// Добавляет ли отпечаток `padding` по правилу BoringSSL.
    fn uses_padding(self) -> bool {
        matches!(self, Self::Chrome | Self::Safari)
    }

    /// Собирает `ClientHello` со случайным содержимым GREASE, `key_share` и
    /// клиентского случайного значения.
    ///
    /// `session_id` не выдумывается здесь: он приходит снаружи целиком —
    /// местом для настоящей случайности (обычный клиент) или для
    /// зашифрованных данных опознания Reality (следующий шаг фазы 19).
    /// Смотрите [`crate::random_session_id`] для первого случая.
    pub fn build(
        self,
        server_name: &Address,
        session_id: [u8; 32],
    ) -> UtlsResult<(ClientHello, Vec<KeyExchange>)> {
        self.build_with_rng(&mut rand::thread_rng(), server_name, session_id)
    }

    /// То же самое, но с генератором случайности, который можно
    /// зафиксировать в тесте.
    pub fn build_with_rng(
        self,
        rng: &mut impl RngCore,
        server_name: &Address,
        session_id: [u8; 32],
    ) -> UtlsResult<(ClientHello, Vec<KeyExchange>)> {
        let host = server_name
            .as_domain()
            .ok_or_else(|| UtlsError::sni_requires_domain(server_name))?;

        let (cipher_suites, compression_methods, extensions, keys) = match self {
            Self::Chrome => {
                let (extensions, keys) = chrome::build(rng, host)?;
                (
                    chrome::CIPHER_SUITES,
                    chrome::COMPRESSION_METHODS,
                    extensions,
                    keys,
                )
            }
            Self::Firefox => {
                let (extensions, keys) = firefox::build(rng, host)?;
                (
                    firefox::CIPHER_SUITES,
                    firefox::COMPRESSION_METHODS,
                    extensions,
                    keys,
                )
            }
            Self::Safari => {
                let (extensions, keys) = safari::build(rng, host)?;
                (
                    safari::CIPHER_SUITES,
                    safari::COMPRESSION_METHODS,
                    extensions,
                    keys,
                )
            }
        };

        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);

        let handshake = client_hello::assemble(
            client_hello::Fields {
                random,
                session_id,
                cipher_suites,
                compression_methods,
                extensions,
            },
            self.shuffles_extensions(),
            self.uses_padding(),
            rng,
        );

        Ok((
            ClientHello {
                handshake,
                session_id,
                random,
            },
            keys,
        ))
    }
}

impl FromStr for Fingerprint {
    type Err = UtlsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chrome" => Ok(Self::Chrome),
            "firefox" => Ok(Self::Firefox),
            "safari" => Ok(Self::Safari),
            other => Err(UtlsError::config(format!(
                "неизвестный отпечаток `{other}`: известны chrome, firefox, safari"
            ))),
        }
    }
}

/// Собранный `ClientHello`, готовый лечь в TLS-запись.
pub struct ClientHello {
    handshake: Vec<u8>,
    /// `SessionID`, с которым он был собран, — тот же, что дали на входе.
    pub session_id: [u8; 32],
    /// Клиентское случайное значение (`ClientHello.random`).
    pub random: [u8; 32],
}

impl std::fmt::Debug for ClientHello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `session_id` у Reality несёт зашифрованные данные опознания — не
        // секрет в строгом смысле (шифрует его сам Reality, не этот крейт),
        // но и печатать байты, которые выглядят как ключ, незачем (AGENTS.md
        // §5.2 — на этот случай лучше перестраховаться, чем разбираться
        // постфактум, что именно утекло в журнал).
        f.debug_struct("ClientHello")
            .field("handshake_len", &self.handshake.len())
            .finish_non_exhaustive()
    }
}

impl ClientHello {
    /// Смещение `SessionID` в [`Self::handshake_bytes`]: 4 байта заголовка
    /// рукопожатия (тип и трёхбайтная длина, см. [`crate::record`]) + 2 байта
    /// `legacy_version` + 32 байта `random` + 1 байт длины `SessionID` = 39.
    ///
    /// Не зависит ни от отпечатка, ни от перемешивания расширений: `random` и
    /// то, что перед ним, — фиксированная по длине голова сообщения, а
    /// расширения идут дальше, за шифрами и методами сжатия. У uTLS то же
    /// самое названо явным числом с тем же комментарием: `hello.Raw[39:]
    /// // the fixed location of \`Session ID\`` (`Xray-core`,
    /// `transport/internet/reality/reality.go`, ревизия `cd4ce97`, строка 157
    /// в функции `UClient`).
    pub const SESSION_ID_OFFSET: usize = 39;

    /// Заменяет `SessionID` в уже собранном сообщении на зашифрованные данные
    /// опознания Reality.
    ///
    /// Существует только ради Reality: обычный клиент получает готовый
    /// `SessionID` через [`Fingerprint::build`] и вызывать это незачем.
    /// Reality не может сделать наоборот (передать готовые байты в `build`
    /// сразу) — шифрование данных опознания использует в качестве
    /// дополнительных данных (AAD) весь `ClientHello` целиком, а он неизвестен
    /// до сборки. Поэтому порядок такой: собрать `ClientHello` с нулевым
    /// `SessionID`, зашифровать данные опознания с этим `ClientHello` в
    /// качестве AAD, подменить нули результатом — длина не меняется, и
    /// `padding`, посчитанный на первом шаге, остаётся верным.
    pub fn patch_session_id(&mut self, session_id: [u8; 32]) {
        let start = Self::SESSION_ID_OFFSET;
        self.handshake[start..start + 32].copy_from_slice(&session_id);
        self.session_id = session_id;
    }

    /// Сообщение рукопожатия целиком: заголовок (тип и длина) и тело.
    pub fn handshake_bytes(&self) -> &[u8] {
        &self.handshake
    }

    /// То же самое, обёрнутое в запись TLS, — то, что уходит в сокет первым.
    pub fn record_bytes(&self) -> Vec<u8> {
        record::wrap_record(&self.handshake)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Address {
        Address::domain("example.com")
    }

    #[test]
    fn all_three_fingerprints_parse_by_name() {
        assert_eq!(
            "chrome".parse::<Fingerprint>().expect("разбирается"),
            Fingerprint::Chrome
        );
        assert_eq!(
            "firefox".parse::<Fingerprint>().expect("разбирается"),
            Fingerprint::Firefox
        );
        assert_eq!(
            "safari".parse::<Fingerprint>().expect("разбирается"),
            Fingerprint::Safari
        );
        assert!("edge".parse::<Fingerprint>().is_err());
    }

    #[test]
    fn a_numeric_host_is_refused_before_any_bytes_are_built() {
        let ip = Address::Ip("203.0.113.1".parse().expect("адрес"));
        let err = Fingerprint::Chrome
            .build(&ip, [0; 32])
            .expect_err("IP не годится для SNI");
        assert!(err.to_string().contains("203.0.113.1"));
    }

    #[test]
    fn every_fingerprint_builds_a_well_formed_handshake_header() {
        for fingerprint in [
            Fingerprint::Chrome,
            Fingerprint::Firefox,
            Fingerprint::Safari,
        ] {
            let (hello, keys) = fingerprint.build(&host(), [7; 32]).expect("собирается");
            let bytes = hello.handshake_bytes();
            assert_eq!(bytes[0], record::HANDSHAKE_TYPE_CLIENT_HELLO);
            let body_len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as usize;
            assert_eq!(bytes.len(), 4 + body_len);
            assert!(!keys.is_empty());
            assert_eq!(
                hello.session_id, [7; 32],
                "SessionID пришёл снаружи, не выдуман"
            );
        }
    }

    #[test]
    fn the_record_wraps_the_handshake_message_unchanged() {
        let (hello, _) = Fingerprint::Firefox
            .build(&host(), [0; 32])
            .expect("собирается");
        let record_bytes = hello.record_bytes();
        assert_eq!(&record_bytes[5..], hello.handshake_bytes());
    }

    #[test]
    fn two_builds_of_the_same_fingerprint_differ() {
        // Client random и GREASE выбираются заново на каждый вызов — иначе
        // все наши подключения были бы отличимы уже по повторному random.
        let (first, _) = Fingerprint::Chrome
            .build(&host(), [0; 32])
            .expect("собирается");
        let (second, _) = Fingerprint::Chrome
            .build(&host(), [0; 32])
            .expect("собирается");
        assert_ne!(first.handshake_bytes(), second.handshake_bytes());
    }

    #[test]
    fn debug_does_not_print_raw_session_id_bytes() {
        let (hello, _) = Fingerprint::Safari
            .build(&host(), [0xAB; 32])
            .expect("собирается");
        let printed = format!("{hello:?}");
        assert!(!printed.contains("171")); // 0xAB как десятичное число
    }

    #[test]
    fn patching_the_session_id_only_touches_those_32_bytes() {
        for fingerprint in [
            Fingerprint::Chrome,
            Fingerprint::Firefox,
            Fingerprint::Safari,
        ] {
            let (mut hello, _) = fingerprint.build(&host(), [0; 32]).expect("собирается");
            let before = hello.handshake_bytes().to_vec();

            hello.patch_session_id([0xEE; 32]);

            let after = hello.handshake_bytes();
            assert_eq!(after.len(), before.len(), "длина не меняется");
            assert_eq!(hello.session_id, [0xEE; 32]);
            let start = ClientHello::SESSION_ID_OFFSET;
            assert_eq!(&after[start..start + 32], &[0xEE; 32]);
            // Всё вокруг SessionID — то же самое, что было.
            assert_eq!(&after[..start], &before[..start]);
            assert_eq!(&after[start + 32..], &before[start + 32..]);
        }
    }

    #[test]
    fn the_session_id_offset_points_at_the_length_prefixed_session_id() {
        // Байт перед данными — их длина (32), значит смещение верно указывает
        // не куда-то ещё, а на них самих.
        let (hello, _) = Fingerprint::Chrome
            .build(&host(), [0x11; 32])
            .expect("собирается");
        let bytes = hello.handshake_bytes();
        assert_eq!(bytes[ClientHello::SESSION_ID_OFFSET - 1], 32);
        assert_eq!(
            &bytes[ClientHello::SESSION_ID_OFFSET..ClientHello::SESSION_ID_OFFSET + 32],
            &[0x11; 32]
        );
    }
}
