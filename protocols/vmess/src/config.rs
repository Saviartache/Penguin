//! Параметры: адрес сервера, идентичность, чем шифруется тело, транспорт.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_core::uuid::Uuid;
use penguin_transport::tls::{ALPN_H2, ALPN_HTTP11, TlsConfig};
use serde::{Deserialize, Serialize};

use crate::crypto::Cipher;
use crate::crypto::id::resolve;
use crate::error::{VmessError, VmessResult};

/// Чем шифруется соединение до сервера — то же различие, что и у VLESS.
///
/// У VMess своё шифрование тела есть всегда (см. [`Cipher`]), и это поле —
/// **транспортный** слой поверх него: TLS снаружи или его отсутствие. Двух
/// одинаково называемых понятий два намеренно, а не одно: спутать их значит
/// решить, что `security = "none"` здесь означает то же, что байт шифра в
/// протоколе VMess (`"security"` в терминах самого протокола, у нас —
/// [`Cipher`]), а это не так.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// TLS. Обычный случай.
    #[default]
    Tls,
    /// Ничего. Законно, когда TLS снимает кто-то другой — сеть доставки
    /// перед сервером. Само по себе не защищает даже то немногое, чего
    /// [`Cipher`] не защищает.
    None,
}

/// Чем поток переносится.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Голый поток.
    #[default]
    Tcp,
    /// WebSocket.
    Ws,
    /// `Upgrade` без кадров.
    Httpupgrade,
}

impl Transport {
    /// Нужны ли путь и заголовок `Host`.
    pub fn is_http(self) -> bool {
        matches!(self, Self::Ws | Self::Httpupgrade)
    }

    /// Что объявлять в ALPN, если человек не задал своё.
    pub fn default_alpn(self) -> &'static [&'static [u8]] {
        match self {
            Self::Tcp => &[ALPN_H2, ALPN_HTTP11],
            Self::Ws | Self::Httpupgrade => &[ALPN_HTTP11],
        }
    }
}

/// Настройки подключения к серверу VMess.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmessConfig {
    /// Адрес сервера: `example.com:443`.
    pub server: String,

    /// Идентичность пользователя.
    ///
    /// Канонический UUID разбирается как обычно. Строка, которая UUID не
    /// является, — так провайдеры иногда записывают ссылки `vmess://` —
    /// сворачивается в шестнадцать байт через MD5 (`crate::crypto::id`), тем
    /// же способом, каким это делают клиенты семейства v2ray. В журнал не
    /// уходит: см. [`std::fmt::Debug`].
    pub id: String,

    /// `alterId` legacy-схемы.
    ///
    /// Поддерживается только `0`: только AEAD-заголовок, без MD5-опознания.
    /// Ненулевое значение — ошибка настроек, а не тихое переключение на
    /// старый режим.
    #[serde(default)]
    pub alter_id: u32,

    /// Чем шифруется тело.
    #[serde(default)]
    pub cipher: Cipher,

    /// Чем шифруется соединение до сервера — TLS или его отсутствие.
    #[serde(default)]
    pub security: Security,

    /// TLS. Значимо при `security = "tls"`.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Чем переносится поток.
    #[serde(default)]
    pub transport: Transport,

    /// Путь запроса для `ws` и `httpupgrade`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Заголовок `Host` для них же.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// Пускать ли UDP.
    #[serde(default = "yes")]
    pub udp: bool,
}

/// Умолчание для [`VmessConfig::udp`].
const fn yes() -> bool {
    true
}

impl std::fmt::Debug for VmessConfig {
    /// `id` — учётные данные не хуже пароля (`AGENTS.md` §5.2): заглушка
    /// вместо значения, а не производный вывод, который напечатал бы его как
    /// есть.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessConfig")
            .field("server", &self.server)
            .field("id", &"скрыт")
            .field("alter_id", &self.alter_id)
            .field("cipher", &self.cipher)
            .field("security", &self.security)
            .field("transport", &self.transport)
            .field("udp", &self.udp)
            .finish()
    }
}

impl VmessConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> VmessResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| VmessError::config(format!("адрес сервера `{raw}`: {e}")))?;

        if endpoint.ports.is_hopping() {
            return Err(VmessError::config(
                "VMess не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Идентичность, приведённая к UUID.
    pub fn uuid(&self) -> Uuid {
        resolve(&self.id)
    }

    /// Путь запроса для `ws` и `httpupgrade`.
    pub fn path(&self) -> &str {
        match self.path.as_deref().map(str::trim) {
            Some(path) if !path.is_empty() => path,
            _ => "/",
        }
    }

    /// Имя узла в заголовке `Host`.
    pub fn host(&self) -> VmessResult<String> {
        if let Some(host) = self
            .host
            .as_deref()
            .map(str::trim)
            .filter(|host| !host.is_empty())
        {
            return Ok(host.to_owned());
        }
        if let Some(sni) = self
            .tls
            .sni
            .as_deref()
            .map(str::trim)
            .filter(|sni| !sni.is_empty())
        {
            return Ok(sni.to_owned());
        }
        Ok(match self.endpoint()?.0 {
            Address::Domain(domain) => domain,
            Address::Ip(ip) => ip.to_string(),
        })
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> VmessResult<()> {
        self.endpoint()?;

        if self.id.trim().is_empty() {
            return Err(VmessError::config(
                "идентичность не задана: сервер отличает своих только по ней",
            ));
        }
        if self.alter_id != 0 {
            return Err(VmessError::config(format!(
                "alterId = {}: поддерживается только 0 — старый режим с MD5-опознанием \
                 (alterId > 0) снят с поддержки и у самого v2ray, а его согласование ломается \
                 о расхождение часов. Оставьте поле пустым или впишите 0",
                self.alter_id
            )));
        }
        if self.cipher == Cipher::Zero {
            tracing::warn!(
                "VMess с шифром `zero`: тело идёт без шифрования и без единой границы куска — \
                 опаснее `none`, где кадр хотя бы сохраняется"
            );
            if self.udp {
                return Err(VmessError::config(
                    "шифр `zero` не кадрует тело вовсе, и датаграммам не за что зацепиться: \
                     либо выключите UDP в этом профиле, либо выберите другой шифр",
                ));
            }
        }

        match self.security {
            Security::Tls => self.tls.validate()?,
            Security::None => {
                if tls_is_set(&self.tls) {
                    return Err(VmessError::config(
                        "настройки TLS заданы при `security = \"none\"`: \
                         либо включите TLS, либо уберите их",
                    ));
                }
                tracing::warn!(
                    "VMess без TLS: адрес назначения и заголовок уходят по сети открытым \
                     текстом — это законно, только если TLS снимает кто-то перед сервером"
                );
            }
        }

        if !self.transport.is_http() && (self.path.is_some() || self.host.is_some()) {
            return Err(VmessError::config(
                "путь и `Host` заданы у переноса без HTTP: выберите `ws` или `httpupgrade`",
            ));
        }
        if self.transport.is_http() && !self.path().starts_with('/') {
            return Err(VmessError::config("путь обязан начинаться с `/`"));
        }
        Ok(())
    }
}

/// Настройки TLS кто-то трогал.
fn tls_is_set(tls: &TlsConfig) -> bool {
    tls.sni.is_some()
        || tls.insecure
        || tls.pin_sha256.is_some()
        || tls.ca.is_some()
        || !tls.alpn.is_empty()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn config() -> VmessConfig {
        VmessConfig {
            server: "example.com:443".to_owned(),
            id: TEXT.to_owned(),
            ..VmessConfig::default()
        }
    }

    #[test]
    fn a_good_config_passes() {
        config().validate().expect("настройки верны");
    }

    #[test]
    fn an_empty_id_is_refused() {
        let config = VmessConfig {
            id: "   ".to_owned(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_password_instead_of_a_uuid_is_accepted() {
        // Ссылки от провайдеров иногда несут произвольный текст вместо
        // UUID — сворачивается в шестнадцать байт через MD5, а не
        // отвергается.
        let config = VmessConfig {
            id: "моя кодовая фраза".to_owned(),
            ..config()
        };
        config.validate().expect("произвольный текст допустим");
        assert!(!config.uuid().is_nil());
    }

    #[test]
    fn a_nonzero_alter_id_is_refused_by_name() {
        let config = VmessConfig {
            alter_id: 8,
            ..config()
        };
        let err = config.validate().expect_err("старый режим не поддержан");
        assert!(err.to_string().contains("alterId"), "{err}");
    }

    #[test]
    fn zero_cipher_together_with_udp_is_refused() {
        let config = VmessConfig {
            cipher: Cipher::Zero,
            udp: true,
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_cipher_without_udp_is_allowed() {
        let config = VmessConfig {
            cipher: Cipher::Zero,
            udp: false,
            ..config()
        };
        config.validate().expect("без UDP `zero` законен");
    }

    #[test]
    fn tls_settings_without_tls_are_refused() {
        let mut config = VmessConfig {
            security: Security::None,
            ..config()
        };
        config.tls.sni = Some("cdn.example.com".to_owned());
        assert!(config.validate().is_err());
    }

    #[test]
    fn http_settings_belong_to_http_transports() {
        let config = VmessConfig {
            path: Some("/ws".to_owned()),
            ..config()
        };
        assert!(config.validate().is_err());

        let config = VmessConfig {
            transport: Transport::Ws,
            ..config
        };
        config.validate().expect("под `ws` это законно");
    }

    #[test]
    fn the_id_is_read_from_the_settings() {
        let params = json!({ "server": "a.io:443", "id": TEXT });
        let config: VmessConfig = serde_json::from_value(params).expect("разбирается");
        assert_eq!(config.uuid().to_string(), TEXT);
        assert!(config.udp);
        assert_eq!(config.cipher, Cipher::Auto);
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let params = json!({ "server": "a.io:443", "id": TEXT, "uid": TEXT });
        assert!(serde_json::from_value::<VmessConfig>(params).is_err());
    }

    #[test]
    fn the_id_never_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains("b831"), "{shown}");
    }
}
