//! Параметры: адрес прокси, имя, пароль и — для `https` — настройки TLS.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use serde::{Deserialize, Serialize};

use crate::error::{HttpProxyError, HttpProxyResult};

/// Настройки подключения к прокси HTTP CONNECT.
///
/// `Debug` реализован вручную ниже — производный вывел бы пароль в журнал.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpProxyConfig {
    /// Адрес прокси: `proxy.example.com:8080`.
    pub server: String,

    /// Имя пользователя. Пусто — прокси без пароля.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Пароль.
    ///
    /// В `Debug` не попадает: вывод пишется вручную ниже.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// TLS до прокси. Относится только к протоколу `https`.
    #[serde(default)]
    pub tls: TlsConfig,
}

/// Настройки TLS.
///
/// Полей два, а не четыре, как у Hysteria 2: прокси под TLS — это обычный
/// сервер с обычным сертификатом, и закрепление отпечатка с своим корневым
/// сертификатом здесь пока никому не понадобилось. Место для них есть — но
/// заводить поле, которого никто не просил, значит заводить поле, которое
/// некому проверить.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Имя, подставляемое в TLS вместо адреса прокси.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,

    /// Не проверять сертификат.
    ///
    /// Снимает единственную защиту от подмены прокси. Держится отдельным
    /// полем именно затем, чтобы интерфейс мог сказать об этом вслух.
    #[serde(default)]
    pub insecure: bool,
}

impl TlsConfig {
    /// Настройки TLS кто-то трогал.
    pub fn is_set(&self) -> bool {
        self.sni.is_some() || self.insecure
    }
}

impl HttpProxyConfig {
    /// Разбирает адрес прокси.
    pub fn endpoint(&self) -> HttpProxyResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| HttpProxyError::config(format!("адрес прокси `{raw}`: {e}")))?;

        // Диапазон портов — это смена порта на ходу, и у HTTP-прокси её нет.
        // Молча взять первый порт значило бы подключаться не туда, куда
        // просили.
        if endpoint.ports.is_hopping() {
            return Err(HttpProxyError::config(
                "HTTP-прокси не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Имя и пароль, если они заданы.
    pub fn credentials(&self) -> Option<(&str, &str)> {
        let username = self.username.as_deref().filter(|name| !name.is_empty())?;
        Some((username, self.password.as_deref().unwrap_or_default()))
    }

    /// Имя, которое подставляется в TLS.
    ///
    /// Явно заданное `sni` сильнее: прокси за подменённым адресом всё равно
    /// ждёт своё имя, и без этого сертификат не сойдётся. Прокси, заданный
    /// адресом, — не ошибка: SNI в рукопожатие тогда просто не попадает, а
    /// сертификат сверяется с адресом.
    pub fn server_name(&self) -> HttpProxyResult<String> {
        if let Some(sni) = &self.tls.sni
            && !sni.is_empty()
        {
            return Ok(sni.clone());
        }
        Ok(match self.endpoint()?.0 {
            Address::Domain(domain) => domain,
            // Без скобок и для IPv6: rustls ждёт сам адрес.
            Address::Ip(ip) => ip.to_string(),
        })
    }

    /// Проверяет настройки, не устанавливая соединения.
    ///
    /// `secure` — под TLS ли разговор с прокси. От него зависит не только
    /// проверка полей: блок `tls` в профиле без TLS означает, что человек
    /// выбрал не тот протокол, и промолчать здесь значило бы отдать пароль в
    /// открытую ровно тогда, когда он просил обратного.
    pub fn validate(&self, secure: bool) -> HttpProxyResult<()> {
        self.endpoint()?;

        if self.username.as_deref().is_none_or(str::is_empty)
            && self.password.as_deref().is_some_and(|p| !p.is_empty())
        {
            return Err(HttpProxyError::config(
                "задан пароль без имени пользователя: в заголовке они идут только парой",
            ));
        }
        if !secure && self.tls.is_set() {
            return Err(HttpProxyError::config(
                "настройки TLS заданы у протокола без TLS: выберите `https`",
            ));
        }
        if secure {
            self.server_name()?;
        }
        Ok(())
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями: строка «первые
// четыре символа» — это уже утечка, если паролей у пользователя два-три.
impl std::fmt::Debug for HttpProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpProxyConfig")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<скрыт>"))
            .field("tls", &self.tls)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config(server: &str) -> HttpProxyConfig {
        HttpProxyConfig {
            server: server.to_owned(),
            ..HttpProxyConfig::default()
        }
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config("proxy.example.com:8080")
            .endpoint()
            .expect("разбирается");
        assert_eq!(host.as_domain(), Some("proxy.example.com"));
        assert_eq!(port, 8080);

        let (host, _) = config("[2001:db8::1]:3128")
            .endpoint()
            .expect("разбирается");
        assert!(host.as_ip().is_some_and(|ip| ip.is_ipv6()));
    }

    #[test]
    fn refuses_an_address_without_a_port() {
        // Порт прокси не угадывается: 8080, 3128 и 8118 встречаются одинаково
        // часто.
        assert!(config("proxy.example.com").endpoint().is_err());
    }

    #[test]
    fn tls_settings_in_a_plain_profile_are_refused() {
        // Иначе человек ставит «не проверять сертификат», видит, что профиль
        // сохранился, и уверен, что TLS есть, — а пароль всё это время уходит
        // открытым текстом.
        let mut config = config("proxy.example.com:8080");
        config.tls.insecure = true;
        assert!(config.validate(false).is_err());
        config.validate(true).expect("под TLS это законно");
    }

    #[test]
    fn the_tls_name_falls_back_to_the_address() {
        let config = config("proxy.example.com:8443");
        assert_eq!(config.server_name().expect("имя"), "proxy.example.com");

        let mut config = config;
        config.tls.sni = Some("real.example.com".to_owned());
        assert_eq!(config.server_name().expect("имя"), "real.example.com");
    }

    #[test]
    fn an_ip_proxy_needs_no_sni() {
        let config = config("203.0.113.5:8443");
        assert_eq!(config.server_name().expect("имя"), "203.0.113.5");
        config.validate(true).expect("настройки верны");
    }

    #[test]
    fn a_password_without_a_name_is_reported() {
        let config = HttpProxyConfig {
            password: Some("секрет".to_owned()),
            ..config("proxy.example.com:8080")
        };
        assert!(config.validate(false).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let raw = json!({ "server": "proxy.example.com:8080", "user": "penguin" });
        assert!(serde_json::from_value::<HttpProxyConfig>(raw).is_err());
    }

    #[test]
    fn debug_hides_the_password() {
        let config = HttpProxyConfig {
            username: Some("penguin".to_owned()),
            password: Some("секрет".to_owned()),
            ..config("proxy.example.com:8080")
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("секрет"), "пароль в Debug: {rendered}");
        assert!(rendered.contains("<скрыт>"));
    }
}
