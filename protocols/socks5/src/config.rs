//! Параметры: адрес прокси, имя, пароль, разрешение на UDP.
//!
//! Полей мало, и это свойство самого протокола: договариваться в SOCKS5 не о
//! чем — ни шифрования, ни транспорта, ни версий. Всё, что есть, — куда
//! стучаться и под каким именем.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_transport::tls::TlsConfig;
use serde::{Deserialize, Serialize};

use crate::error::{Socks5Error, Socks5Result};

/// Настройки подключения к прокси SOCKS5.
///
/// `Debug` реализован вручную ниже — производный вывел бы пароль в журнал.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socks5Config {
    /// Адрес прокси: `127.0.0.1:1080`.
    pub server: String,

    /// Имя пользователя. Пусто — прокси без пароля.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Пароль.
    ///
    /// В `Debug` не попадает: вывод пишется вручную ниже.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// TLS до прокси. Относится только к протоколу `socks5-tls`.
    ///
    /// Заворачивается в него **только управляющее соединение**: датаграммы
    /// `UDP ASSOCIATE` идут мимо, открытым текстом. Это свойство протокола, а
    /// не недоделка (см. документ крейта), и окно обязано сказать о нём вслух.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Пускать ли UDP через прокси.
    ///
    /// По умолчанию да, но выключатель нужен: `UDP ASSOCIATE` поддерживают
    /// не все прокси, а маршрутизатор обязан знать заранее — направление,
    /// не умеющее UDP, не должно получить DNS-запрос и молча его потерять.
    #[serde(default = "yes")]
    pub udp: bool,
}

/// Умолчание для [`Socks5Config::udp`].
const fn yes() -> bool {
    true
}

impl Socks5Config {
    /// Разбирает адрес прокси.
    pub fn endpoint(&self) -> Socks5Result<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| Socks5Error::config(format!("адрес прокси `{raw}`: {e}")))?;

        // Диапазон портов — это смена порта на ходу, и у SOCKS5 её нет:
        // соединение открывается на каждое подключение заново, и «сменить»
        // тут нечего. Молча взять первый порт значило бы подключаться не туда,
        // куда просили.
        if endpoint.ports.is_hopping() {
            return Err(Socks5Error::config(
                "SOCKS5 не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Имя и пароль, если прокси их спрашивает.
    ///
    /// Пароль без имени — не «анонимный вход с паролем», а незаполненное поле:
    /// в RFC 1929 имя обязательно. Разбирается это в [`Self::validate`].
    pub fn credentials(&self) -> Option<(&str, &str)> {
        let username = self.username.as_deref().filter(|name| !name.is_empty())?;
        Some((username, self.password.as_deref().unwrap_or_default()))
    }

    /// Настройки TLS кто-то трогал.
    ///
    /// Нужно, чтобы отличить «человек выбрал не тот протокол» от «поля просто
    /// нет». Блок `tls` в профиле без TLS означает первое, и промолчать здесь
    /// значило бы отдать пароль в открытую ровно тогда, когда просили обратного.
    fn tls_is_set(&self) -> bool {
        let tls = &self.tls;
        tls.sni.is_some()
            || tls.insecure
            || tls.pin_sha256.is_some()
            || tls.ca.is_some()
            || !tls.alpn.is_empty()
    }

    /// Проверяет настройки, не устанавливая соединения.
    ///
    /// `secure` — под TLS ли разговор с прокси.
    pub fn validate(&self, secure: bool) -> Socks5Result<()> {
        self.endpoint()?;

        if !secure && self.tls_is_set() {
            return Err(Socks5Error::config(
                "настройки TLS заданы у протокола без TLS: выберите `socks5-tls`",
            ));
        }
        if secure {
            self.tls.validate()?;
        }

        if self.username.as_deref().is_none_or(str::is_empty)
            && self.password.as_deref().is_some_and(|p| !p.is_empty())
        {
            return Err(Socks5Error::config(
                "задан пароль без имени пользователя: в SOCKS5 они идут только парой",
            ));
        }
        if let Some((username, password)) = self.credentials() {
            // Длина пишется одним байтом (RFC 1929): то, что длиннее, в запрос
            // просто не поместится.
            if username.len() > 255 || password.len() > 255 {
                return Err(Socks5Error::config(
                    "имя и пароль SOCKS5 не длиннее 255 байт каждый",
                ));
            }
        }
        Ok(())
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями: строка «первые
// четыре символа» — это уже утечка, если паролей у пользователя два-три.
impl std::fmt::Debug for Socks5Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5Config")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<скрыт>"))
            .field("udp", &self.udp)
            .field("tls", &self.tls)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config(server: &str) -> Socks5Config {
        Socks5Config {
            server: server.to_owned(),
            username: None,
            password: None,
            tls: TlsConfig::default(),
            udp: true,
        }
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config("127.0.0.1:1080").endpoint().expect("разбирается");
        assert!(host.as_ip().is_some());
        assert_eq!(port, 1080);

        let (host, _) = config("proxy.example.com:1080")
            .endpoint()
            .expect("разбирается");
        assert_eq!(host.as_domain(), Some("proxy.example.com"));

        let (host, port) = config("[2001:db8::1]:1080")
            .endpoint()
            .expect("разбирается");
        assert!(host.as_ip().is_some_and(|ip| ip.is_ipv6()));
        assert_eq!(port, 1080);
    }

    #[test]
    fn refuses_a_port_range() {
        // Смены порта у SOCKS5 нет; молча взять первый порт значило бы
        // подключаться не туда, куда просили.
        assert!(config("127.0.0.1:1080-1090").endpoint().is_err());
    }

    #[test]
    fn refuses_an_address_without_a_port() {
        assert!(config("127.0.0.1").endpoint().is_err());
        assert!(config("").endpoint().is_err());
    }

    #[test]
    fn a_proxy_without_a_password_needs_no_credentials() {
        assert!(config("127.0.0.1:1080").credentials().is_none());
        config("127.0.0.1:1080")
            .validate(false)
            .expect("настройки верны");
    }

    #[test]
    fn an_empty_password_still_counts_as_credentials() {
        // Прокси, спрашивающий имя и пустой пароль, встречается: пропустить
        // проверку подлинности значило бы получить отказ на ровном месте.
        let config = Socks5Config {
            username: Some("penguin".to_owned()),
            ..config("127.0.0.1:1080")
        };
        assert_eq!(config.credentials(), Some(("penguin", "")));
        config.validate(false).expect("настройки верны");
    }

    #[test]
    fn a_password_without_a_name_is_reported() {
        // В RFC 1929 имя обязательно; молча отправить пустое — значит получить
        // отказ и гадать, при чём тут пароль.
        let config = Socks5Config {
            password: Some("секрет".to_owned()),
            ..config("127.0.0.1:1080")
        };
        assert!(config.validate(false).is_err());
    }

    #[test]
    fn tls_settings_in_a_plain_profile_are_refused() {
        // Иначе человек ставит «не проверять сертификат», видит, что профиль
        // сохранился, и уверен, что TLS есть, — а пароль и адрес назначения
        // всё это время уходят открытым текстом.
        let mut config = config("127.0.0.1:1080");
        config.tls.insecure = true;
        assert!(config.validate(false).is_err());
        config.validate(true).expect("под TLS это законно");
    }

    #[test]
    fn udp_is_on_unless_it_is_turned_off() {
        let config: Socks5Config =
            serde_json::from_value(json!({ "server": "127.0.0.1:1080" })).expect("разбирается");
        assert!(config.udp);

        let config: Socks5Config =
            serde_json::from_value(json!({ "server": "127.0.0.1:1080", "udp": false }))
                .expect("разбирается");
        assert!(!config.udp);
    }

    #[test]
    fn rejects_an_unknown_field() {
        // Опечатка в имени поля не должна молча превращаться в умолчание:
        // человек напишет `user` и будет гадать, почему прокси его не пускает.
        let raw = json!({ "server": "127.0.0.1:1080", "user": "penguin" });
        assert!(serde_json::from_value::<Socks5Config>(raw).is_err());
    }

    #[test]
    fn debug_hides_the_password() {
        let config = Socks5Config {
            username: Some("penguin".to_owned()),
            password: Some("секрет".to_owned()),
            ..config("127.0.0.1:1080")
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("секрет"), "пароль в Debug: {rendered}");
        assert!(rendered.contains("<скрыт>"));
    }
}
