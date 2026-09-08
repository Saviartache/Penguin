//! Параметры: адрес сервера, метод шифрования, пароль.
//!
//! Полей мало, и это свойство самого протокола: договариваться в Shadowsocks
//! не о чем — ни рукопожатия, ни версий, ни возможностей. Клиент и сервер
//! обязаны заранее знать одно и то же, иначе не сойдутся вовсе.

use penguin_core::address::Address;
use penguin_core::base64;
use penguin_core::endpoint::ServerEndpoint;
use serde::{Deserialize, Serialize};

use crate::error::{ShadowsocksError, ShadowsocksResult};
use crate::method::ShadowsocksMethod;

/// Настройки подключения к серверу Shadowsocks.
///
/// `Debug` реализован вручную ниже — производный вывел бы пароль в журнал.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksConfig {
    /// Адрес сервера: `example.com:8388`.
    pub server: String,

    /// Метод шифрования. Обязателен: угадать его нельзя.
    ///
    /// Умолчания здесь нет намеренно. Метод — часть договора с сервером, и
    /// подставленный молча даёт соединение, которое открывается и ничего не
    /// передаёт: сервер просто не сможет прочитать первый кусок.
    pub method: ShadowsocksMethod,

    /// Пароль — для методов AEAD; ключ (PSK) в base64 — для методов
    /// `2022-blake3-*`.
    ///
    /// У 2022 это не пароль в обычном смысле: ровно [`Method2022::key_len`]
    /// байт в base64, и длина проверяется в [`ShadowsocksConfig::validate`]
    /// до подключения — сервер с другой длиной ключа не пришлёт даже отказа,
    /// он просто не сможет прочитать первый кусок.
    ///
    /// В `Debug` не попадает: вывод пишется вручную ниже.
    ///
    /// [`Method2022::key_len`]: crate::method::Method2022::key_len
    pub password: String,

    /// Пускать ли UDP через сервер.
    #[serde(default = "yes")]
    pub udp: bool,
}

/// Умолчание для [`ShadowsocksConfig::udp`].
const fn yes() -> bool {
    true
}

impl ShadowsocksConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> ShadowsocksResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| ShadowsocksError::config(format!("адрес сервера `{raw}`: {e}")))?;

        // Диапазон портов — это смена порта на ходу, и у Shadowsocks её нет.
        if endpoint.ports.is_hopping() {
            return Err(ShadowsocksError::config(
                "Shadowsocks не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> ShadowsocksResult<()> {
        self.endpoint()?;

        match self.method {
            ShadowsocksMethod::Aead(_) => {
                if self.password.is_empty() {
                    return Err(ShadowsocksError::config(
                        "пароль не задан: из него выводится ключ, и пустой означает \
                         ключ, который знают все",
                    ));
                }
            }
            // У 2022 поле `password` несёт не пароль, а ключ в base64, и он
            // обязан быть ровно нужной длины — до подключения, а не после
            // молчания сервера.
            ShadowsocksMethod::Aead2022(method) => {
                base64::decode_exact(&self.password, method.key_len(), "ключ Shadowsocks 2022")
                    .map_err(|e| ShadowsocksError::config(e.to_string()))?;
            }
        }
        Ok(())
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями: строка «первые
// четыре символа» — это уже утечка, если паролей у пользователя два-три.
impl std::fmt::Debug for ShadowsocksConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksConfig")
            .field("server", &self.server)
            .field("method", &self.method.name())
            .field("password", &"<скрыт>")
            .field("udp", &self.udp)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::crypto::Method;
    use crate::method::Method2022;

    fn config() -> ShadowsocksConfig {
        ShadowsocksConfig {
            server: "example.com:8388".to_owned(),
            method: ShadowsocksMethod::Aead(Method::Aes256Gcm),
            password: "secret".to_owned(),
            udp: true,
        }
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config().endpoint().expect("разбирается");
        assert_eq!(host.as_domain(), Some("example.com"));
        assert_eq!(port, 8388);

        let config = ShadowsocksConfig {
            server: "[2001:db8::1]:8388".to_owned(),
            ..config()
        };
        assert!(config.endpoint().expect("разбирается").0.as_ip().is_some());
    }

    #[test]
    fn refuses_an_address_without_a_port() {
        // 8388 — обычай, а не правило; молча подставить его значит
        // подключаться не туда.
        let config = ShadowsocksConfig {
            server: "example.com".to_owned(),
            ..config()
        };
        assert!(config.endpoint().is_err());
    }

    #[test]
    fn a_password_is_required() {
        let config = ShadowsocksConfig {
            password: String::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn the_method_has_no_default() {
        // Подставленный молча метод даёт соединение, которое открывается и
        // ничего не передаёт: сервер не прочитает первый кусок.
        let params = json!({ "server": "example.com:8388", "password": "x" });
        assert!(serde_json::from_value::<ShadowsocksConfig>(params).is_err());
    }

    #[test]
    fn the_method_is_read_by_its_usual_name() {
        let params = json!({
            "server": "example.com:8388",
            "method": "chacha20-ietf-poly1305",
            "password": "x"
        });
        let config: ShadowsocksConfig = serde_json::from_value(params).expect("разбирается");
        assert_eq!(
            config.method,
            ShadowsocksMethod::Aead(Method::Chacha20Poly1305)
        );
        assert!(config.udp, "UDP включён, пока его не выключили");
    }

    #[test]
    fn a_stream_cipher_is_refused_by_name() {
        let params = json!({
            "server": "example.com:8388",
            "method": "aes-256-cfb",
            "password": "x"
        });
        assert!(serde_json::from_value::<ShadowsocksConfig>(params).is_err());
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let params = json!({
            "server": "example.com:8388",
            "method": "aes-256-gcm",
            "password": "x",
            "passwort": "y"
        });
        assert!(serde_json::from_value::<ShadowsocksConfig>(params).is_err());
    }

    #[test]
    fn the_password_never_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains("secret"), "{shown}");
    }

    #[test]
    fn a_2022_key_of_the_right_length_validates() {
        let key = penguin_core::base64::encode(&[7u8; 16]);
        let config = ShadowsocksConfig {
            method: ShadowsocksMethod::Aead2022(Method2022::Blake3Aes128Gcm),
            password: key,
            ..config()
        };
        config.validate().expect("ключ ровно нужной длины");
    }

    #[test]
    fn a_2022_key_of_the_wrong_length_names_the_expected_length() {
        // Сервер с ключом не той длины не пришлёт даже отказа — он просто не
        // сможет прочитать первый кусок, и это должно быть видно до
        // подключения, а не после его молчания.
        let key = penguin_core::base64::encode(&[7u8; 10]);
        let config = ShadowsocksConfig {
            method: ShadowsocksMethod::Aead2022(Method2022::Blake3Aes128Gcm),
            password: key,
            ..config()
        };
        let err = config.validate().expect_err("длина не та");
        let text = err.to_string();
        assert!(text.contains("10"), "{text}");
        assert!(text.contains("16"), "{text}");
    }

    #[test]
    fn a_password_that_is_not_base64_is_refused_for_a_2022_method() {
        let config = ShadowsocksConfig {
            method: ShadowsocksMethod::Aead2022(Method2022::Blake3Chacha20Poly1305),
            password: "не ключ и не base64!".to_owned(),
            ..config()
        };
        assert!(config.validate().is_err());
    }
}
