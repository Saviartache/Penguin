//! Настройки Reality: публичный ключ сервера, короткий идентификатор, имя
//! сайта для `ClientHello` и отпечаток браузера.

use penguin_utls::Fingerprint;
use serde::{Deserialize, Serialize};

use crate::reality::error::RealityError;

/// Настройки Reality. Значимы при `security = "reality"`
/// ([`crate::config::Security::Reality`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityConfig {
    /// Публичный ключ сервера X25519, `base64url` без набивки — та же запись,
    /// что печатает `xray x25519` (`Xray-core`, `infra/conf/
    /// transport_security.go`, строка 196:
    /// `base64.RawURLEncoding.DecodeString(c.PublicKey)`, ровно 32 байта после
    /// разбора; независимо подтверждено `sing-box`,
    /// `common/tls/reality_client.go`: `base64.RawURLEncoding.DecodeString(
    /// options.Reality.PublicKey)`).
    pub public_key: String,

    /// Короткий идентификатор: 0-16 шестнадцатеричных цифр (0-8 байт),
    /// объявленный на сервере в списке разрешённых. Короче — дополняется
    /// нулевыми байтами справа (`Xray-core`, тот же файл, строка 205:
    /// `config.ShortId = make([]byte, 8); hex.Decode(config.ShortId, ...)` —
    /// `hex.Decode` в `encoding/hex` пишет ровно `len(src)/2` байт в начало
    /// `dst` и не трогает остаток, оставляя его нулями из `make`).
    #[serde(default)]
    pub short_id: String,

    /// Имя сайта, за который выдаёт себя `ClientHello`: идёт в SNI. Обычно —
    /// домен из `serverNames` настроек сервера (сайт, который Reality
    /// прикрывает).
    pub server_name: String,

    /// Отпечаток браузера, которым собирается `ClientHello`
    /// (`penguin_utls::Fingerprint`) — Chrome, Firefox или Safari; версии
    /// зафиксированы в самом крейте `penguin-utls`.
    #[serde(default = "default_fingerprint")]
    pub fingerprint: Fingerprint,
}

/// Умолчание для [`RealityConfig::fingerprint`].
///
/// `Fingerprint` — чужой тип (`penguin-utls`), и `impl Default` для него
/// здесь запрещён правилом сирот; отдельная функция — обычный способ дать
/// полю умолчание, не трогая чужой крейт.
fn default_fingerprint() -> Fingerprint {
    Fingerprint::Chrome
}

impl RealityConfig {
    /// Публичный ключ сервера как 32 байта X25519.
    pub fn public_key_bytes(&self) -> Result<[u8; 32], RealityError> {
        let decoded = penguin_core::base64::decode_exact(
            self.public_key.trim(),
            32,
            "публичный ключ Reality",
        )
        .map_err(|e| RealityError::Config(format!("`public_key`: {e}")))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        Ok(out)
    }

    /// `short_id`, дополненный нулями до 8 байт.
    pub fn short_id_bytes(&self) -> Result<[u8; 8], RealityError> {
        let trimmed = self.short_id.trim();
        if trimmed.len() > 16 {
            return Err(RealityError::Config(
                "`short_id` длиннее 16 шестнадцатеричных цифр (8 байт)".to_owned(),
            ));
        }
        if !trimmed.len().is_multiple_of(2) {
            return Err(RealityError::Config(
                "`short_id`: нечётное число шестнадцатеричных цифр".to_owned(),
            ));
        }
        let mut out = [0u8; 8];
        for (index, byte) in out.iter_mut().enumerate().take(trimmed.len() / 2) {
            let pair = &trimmed[index * 2..index * 2 + 2];
            *byte = u8::from_str_radix(pair, 16)
                .map_err(|_| RealityError::Config(format!("`short_id`: `{pair}` — не хекс")))?;
        }
        Ok(out)
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> Result<(), RealityError> {
        self.public_key_bytes()?;
        self.short_id_bytes()?;
        if self.server_name.trim().is_empty() {
            return Err(RealityError::Config(
                "`server_name` пуст: Reality подделывает сайт по имени, а не по адресу".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RealityConfig {
        RealityConfig {
            // 32 нулевых байта в base64url без набивки.
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            short_id: "0123abcd".to_owned(),
            server_name: "www.example.com".to_owned(),
            fingerprint: Fingerprint::Chrome,
        }
    }

    #[test]
    fn a_good_config_passes() {
        config().validate().expect("настройки верны");
    }

    #[test]
    fn the_short_id_is_padded_with_zeros_on_the_right() {
        let bytes = RealityConfig {
            short_id: "ab".to_owned(),
            ..config()
        }
        .short_id_bytes()
        .expect("разбирается");
        assert_eq!(bytes, [0xab, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn an_empty_short_id_is_all_zeros() {
        let bytes = RealityConfig {
            short_id: String::new(),
            ..config()
        }
        .short_id_bytes()
        .expect("разбирается");
        assert_eq!(bytes, [0; 8]);
    }

    #[test]
    fn a_short_id_longer_than_eight_bytes_is_refused() {
        let err = RealityConfig {
            short_id: "0123456789abcdef00".to_owned(),
            ..config()
        }
        .validate()
        .expect_err("длиннее 8 байт");
        assert!(err.to_string().contains("short_id"));
    }

    #[test]
    fn a_public_key_of_the_wrong_length_is_refused() {
        let err = RealityConfig {
            public_key: "AAAA".to_owned(),
            ..config()
        }
        .validate()
        .expect_err("не 32 байта");
        assert!(err.to_string().contains("public_key"));
    }

    #[test]
    fn an_empty_server_name_is_refused() {
        let err = RealityConfig {
            server_name: String::new(),
            ..config()
        }
        .validate()
        .expect_err("SNI подделывает сайт по имени");
        assert!(err.to_string().contains("server_name"));
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let params = serde_json::json!({
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "server_name": "www.example.com",
            "extra": "field",
        });
        assert!(serde_json::from_value::<RealityConfig>(params).is_err());
    }

    #[test]
    fn fingerprint_defaults_to_chrome() {
        let params = serde_json::json!({
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "server_name": "www.example.com",
        });
        let config: RealityConfig = serde_json::from_value(params).expect("разбирается");
        assert_eq!(config.fingerprint, Fingerprint::Chrome);
    }
}
