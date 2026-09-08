//! Параметры: адрес сервера, его открытый ключ, пароль, прикрытие, обход DPI.
//!
//! # Почему ключ сервера обязателен
//!
//! На нём стоит всё: опознание сервера, опознание клиента и устойчивость к
//! активной проверке. Без него протокол превратился бы в «пароль открытым
//! текстом внутри случайных байт» — то, что вскрывается перебором по
//! записанному трафику.
//!
//! Пароль при этом тоже обязателен, но роль у него другая: он отличает
//! пользователей одного сервера друг от друга. Один ключ на всех и разные
//! пароли — это то, ради чего вообще нужны две тайны, а не одна.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_transport::aead::Algorithm;
use penguin_transport::desync::{Desync, DesyncConfig};
use penguin_utls::Fingerprint;
use serde::{Deserialize, Serialize};

use crate::error::{PingwinError, PingwinResult};
use crate::wire::keys::PUBLIC_LEN;

/// Имя прикрытия, когда его не задали.
///
/// Годится почти везде: узел существует, отвечает по TLS 1.3 и запрашивается
/// сам по себе так часто, что не выделяется. Задать своё всё равно лучше —
/// имя, одинаковое у всех пользователей клиента, само становится приметой.
pub const DEFAULT_SNI: &str = "www.microsoft.com";

/// Настройки подключения к серверу Pingwin.
///
/// `Debug` реализован вручную ниже — производный вывел бы пароль в журнал.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PingwinConfig {
    /// Адрес сервера: `example.com:443`.
    pub server: String,

    /// Открытый ключ сервера, тридцать два байта в base64.
    pub key: String,

    /// Пароль пользователя.
    ///
    /// В `Debug` не попадает: вывод пишется вручную ниже.
    pub password: String,

    /// Имя, которое уходит в SNI приветствия, — то, что видит DPI.
    pub sni: String,

    /// Чьим `ClientHello` притворяться: `chrome`, `firefox`, `safari`.
    pub fingerprint: Fingerprint,

    /// Шифр записей: `aes-256-gcm` или `chacha20-poly1305`.
    pub cipher: String,

    /// Слать ли первый запрос вместе с приветствием.
    ///
    /// Включено: ради этого протокол и устроен так, как устроен. Повтор
    /// ранних данных закрыт окном ([`crate::wire::replay`]), а не оставлен
    /// на совесть приложения, как в TLS 1.3.
    pub zero_rtt: bool,

    /// Обход DPI первой посылкой.
    pub desync: DesyncConfig,
}

impl Default for PingwinConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            key: String::new(),
            password: String::new(),
            sni: DEFAULT_SNI.to_owned(),
            fingerprint: Fingerprint::Chrome,
            cipher: Algorithm::Aes256Gcm.name().to_owned(),
            zero_rtt: true,
            desync: DesyncConfig::default(),
        }
    }
}

impl PingwinConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> PingwinResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| PingwinError::config(format!("адрес сервера `{raw}`: {e}")))?;

        // Диапазон портов — это смена порта на ходу; у Pingwin её нет:
        // соединение одно на профиль и живёт долго, а смена порта имеет смысл
        // там, где соединений много и каждое короткое.
        if endpoint.ports.is_hopping() {
            return Err(PingwinError::config(
                "pingwin не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Открытый ключ сервера.
    pub fn server_public(&self) -> PingwinResult<[u8; PUBLIC_LEN]> {
        let bytes = penguin_core::base64::decode_exact(self.key.trim(), PUBLIC_LEN, "ключ сервера")
            .map_err(|e| PingwinError::config(format!("ключ сервера: {e}")))?;
        let mut key = [0u8; PUBLIC_LEN];
        let chunk: &[u8; PUBLIC_LEN] = bytes
            .first_chunk()
            .ok_or_else(|| PingwinError::config("ключ сервера не тридцати двух байт"))?;
        key.copy_from_slice(chunk);
        Ok(key)
    }

    /// Имя прикрытия — оно же имя в SNI.
    pub fn cover_name(&self) -> PingwinResult<Address> {
        let name = self.sni.trim();
        if name.is_empty() {
            return Err(PingwinError::config("не задано имя прикрытия"));
        }
        // Отпечаток собирает SNI только по имени: адрес в это поле не кладёт
        // ни один браузер, и приветствие с ним выделялось бы само по себе.
        // Односоставное имя (`localhost`) — то же самое: в SNI такого не
        // бывает, там всегда полное имя узла.
        if name.parse::<std::net::IpAddr>().is_ok() || !name.contains('.') {
            return Err(PingwinError::config(format!(
                "имя прикрытия `{name}` — не доменное имя"
            )));
        }
        Ok(Address::domain(name))
    }

    /// Шифр записей.
    pub fn algorithm(&self) -> PingwinResult<Algorithm> {
        match self.cipher.trim() {
            "" => Ok(Algorithm::Aes256Gcm),
            name if name == Algorithm::Aes256Gcm.name() => Ok(Algorithm::Aes256Gcm),
            name if name == Algorithm::ChaCha20Poly1305.name() => Ok(Algorithm::ChaCha20Poly1305),
            other => Err(PingwinError::config(format!(
                "шифр `{other}`: бывают {} и {}",
                Algorithm::Aes256Gcm.name(),
                Algorithm::ChaCha20Poly1305.name()
            ))),
        }
    }

    /// План обхода DPI.
    pub fn desync(&self) -> PingwinResult<Desync> {
        Ok(self.desync.compile()?)
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> PingwinResult<()> {
        self.endpoint()?;
        self.server_public()?;
        self.cover_name()?;
        self.algorithm()?;
        self.desync()?;

        if self.password.is_empty() {
            return Err(PingwinError::config(
                "не задан пароль: без него сервер не отличит одного пользователя от другого",
            ));
        }
        Ok(())
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями (`AGENTS.md` §5.2).
// Ключ сервера открытый, и прятать его незачем: он и так стоит в ссылке.
impl std::fmt::Debug for PingwinConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingwinConfig")
            .field("server", &self.server)
            .field("key", &self.key)
            .field("password", &"<скрыт>")
            .field("sni", &self.sni)
            .field("fingerprint", &self.fingerprint)
            .field("cipher", &self.cipher)
            .field("zero_rtt", &self.zero_rtt)
            .field("desync", &self.desync)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config() -> PingwinConfig {
        PingwinConfig {
            server: "example.com:443".to_owned(),
            key: penguin_core::base64::encode(&[7u8; PUBLIC_LEN]),
            password: "secret".to_owned(),
            ..PingwinConfig::default()
        }
    }

    #[test]
    fn a_complete_config_passes() {
        config().validate().expect("настройки верны");
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = PingwinConfig {
            server: "[2001:db8::1]:8443".to_owned(),
            ..config()
        }
        .endpoint()
        .expect("разбирается");
        assert!(host.as_ip().is_some_and(|ip| ip.is_ipv6()));
        assert_eq!(port, 8443);
    }

    #[test]
    fn refuses_a_port_range_and_an_address_without_a_port() {
        for server in ["example.com:20000-30000", "example.com"] {
            assert!(
                PingwinConfig {
                    server: server.to_owned(),
                    ..config()
                }
                .endpoint()
                .is_err(),
                "{server}"
            );
        }
    }

    #[test]
    fn a_key_of_the_wrong_length_is_reported_in_the_field() {
        // Обрезанный при копировании ключ — самая частая ошибка, и ответ на
        // неё должен быть в форме, а не через минуту молчания сервера.
        for key in ["", "не base64", &penguin_core::base64::encode(&[7u8; 31])] {
            assert!(
                PingwinConfig {
                    key: key.to_owned(),
                    ..config()
                }
                .server_public()
                .is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn the_cover_name_must_be_a_domain() {
        // Адрес в SNI не кладёт ни один браузер: приветствие с ним выделялось
        // бы само по себе — ровно то, от чего прикрытие и защищает.
        for sni in ["", "203.0.113.5", "localhost"] {
            assert!(
                PingwinConfig {
                    sni: sni.to_owned(),
                    ..config()
                }
                .cover_name()
                .is_err(),
                "{sni}"
            );
        }
        assert!(config().cover_name().is_ok());
    }

    #[test]
    fn a_missing_password_is_reported() {
        assert!(
            PingwinConfig {
                password: String::new(),
                ..config()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn only_the_two_ciphers_that_exist_are_accepted() {
        for (name, expected) in [
            ("aes-256-gcm", Algorithm::Aes256Gcm),
            ("chacha20-poly1305", Algorithm::ChaCha20Poly1305),
            ("", Algorithm::Aes256Gcm),
        ] {
            let config = PingwinConfig {
                cipher: name.to_owned(),
                ..config()
            };
            assert_eq!(config.algorithm().expect("известен"), expected);
        }
        assert!(
            PingwinConfig {
                cipher: "aes-128-gcm".to_owned(),
                ..config()
            }
            .algorithm()
            .is_err(),
            "шифра со 128-битным ключом у протокола нет"
        );
    }

    #[test]
    fn a_broken_desync_section_is_caught_before_connecting() {
        let raw = json!({
            "server": "example.com:443",
            "key": penguin_core::base64::encode(&[7u8; PUBLIC_LEN]),
            "password": "secret",
            "desync": { "strategy": "multi-split" },
        });
        let config: PingwinConfig = serde_json::from_value(raw).expect("разбирается");
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_rtt_is_on_unless_it_is_turned_off() {
        assert!(PingwinConfig::default().zero_rtt);
    }

    #[test]
    fn rejects_an_unknown_field() {
        let raw = json!({
            "server": "example.com:443",
            "key": "x",
            "password": "secret",
            "passwort": "y",
        });
        assert!(serde_json::from_value::<PingwinConfig>(raw).is_err());
    }

    #[test]
    fn debug_hides_the_password() {
        let rendered = format!("{:?}", config());
        assert!(!rendered.contains("secret"), "пароль в Debug: {rendered}");
        assert!(rendered.contains("<скрыт>"));
    }
}
