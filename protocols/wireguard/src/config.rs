//! Параметры: адрес сервера, ключи, адреса интерфейса, MTU, `keepalive`.

use std::net::{Ipv4Addr, Ipv6Addr};

use penguin_core::address::SocketAddress;
use penguin_core::base64;
use serde::{Deserialize, Serialize};

use crate::crypto::constants::{DEFAULT_KEEPALIVE_SECS, DEFAULT_MTU, KEY_LEN, MAX_KEEPALIVE_SECS};
use crate::error::{WireguardError, WireguardResult};

/// Настройки подключения к серверу WireGuard.
///
/// В отличие от потоковых протоколов этого плана, здесь нет ни TLS, ни
/// пароля: подлинность и секретность даёт сама пара ключей X25519.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireguardConfig {
    /// Адрес сервера: `example.com:51820`.
    pub server: SocketAddress,

    /// Собственный приватный ключ, base64, 32 байта.
    ///
    /// В `Debug` не попадает — за этим следит вывод ниже (`AGENTS.md` §5.2).
    pub private_key: String,

    /// Открытый ключ сервера, base64, 32 байта.
    ///
    /// Не секрет сам по себе, но в `Debug` тоже скрыт — рядом с приватным его
    /// проще не печатать вовсе, чем гадать на ревью, какое поле безопасно.
    pub server_public_key: String,

    /// Предварительный ключ (`PresharedKey`), base64, 32 байта.
    ///
    /// Необязателен: спецификация всё равно смешивает его в рукопожатие
    /// (модификатор `psk2`), а незаданный ключ — это все нули, обычное
    /// поведение `wg(8)`, а не заглушка этого крейта.
    #[serde(default)]
    pub preshared_key: Option<String>,

    /// Адрес IPv4 интерфейса вместе с длиной префикса: `10.0.0.2/32`.
    pub address_ipv4: String,

    /// Адрес IPv6 интерфейса вместе с длиной префикса, если сервер его выдал.
    #[serde(default)]
    pub address_ipv6: Option<String>,

    /// Наибольший пакет, который направление берёт целиком.
    ///
    /// По умолчанию 1420 — 1500 внешних минус заголовки IP/UDP/WireGuard
    /// (см. `crate::crypto::constants::DEFAULT_MTU`).
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// Интервал `PersistentKeepalive` в секундах. Ноль — выключен.
    ///
    /// За NAT без него шлюз забывает отображение адреса через минуту-другую,
    /// и путь назад пропадает молча — соединение выглядит оборванным без
    /// единой ошибки. По умолчанию 25 — то же значение, что `wg(8)` называет
    /// разумным для интерфейса за NAT.
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u32,

    /// Три зарезервированных байта заголовка (после байта типа сообщения).
    ///
    /// У обычного WireGuard они всегда нулевые. Ненулевые нужны только там,
    /// где сервер сам их проверяет как метку своего трафика поверх обычного
    /// протокола, — настройка существует ради совместимости с такими
    /// серверами, а не ради самого клиента.
    #[serde(default)]
    pub reserved: [u8; 3],
}

/// Умолчание для [`WireguardConfig::mtu`].
const fn default_mtu() -> u16 {
    DEFAULT_MTU
}

/// Умолчание для [`WireguardConfig::keepalive_secs`].
const fn default_keepalive_secs() -> u32 {
    DEFAULT_KEEPALIVE_SECS
}

// Написано руками, а не выведено: производный `Default` дал бы `mtu: 0` и
// `keepalive_secs: 0`, то есть настройки, собранные в коде, вели бы себя не
// так, как ровно те же настройки, прочитанные из файла.
impl Default for WireguardConfig {
    fn default() -> Self {
        Self {
            server: SocketAddress::ip(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            private_key: String::new(),
            server_public_key: String::new(),
            preshared_key: None,
            address_ipv4: String::new(),
            address_ipv6: None,
            mtu: default_mtu(),
            keepalive_secs: default_keepalive_secs(),
            reserved: [0, 0, 0],
        }
    }
}

impl WireguardConfig {
    /// Разбирает и проверяет приватный ключ.
    pub fn private_key_bytes(&self) -> WireguardResult<[u8; KEY_LEN]> {
        decode_key(&self.private_key, "приватный ключ")
    }

    /// Разбирает и проверяет открытый ключ сервера.
    pub fn server_public_key_bytes(&self) -> WireguardResult<[u8; KEY_LEN]> {
        decode_key(&self.server_public_key, "открытый ключ сервера")
    }

    /// Разбирает предварительный ключ, если он задан. Незаданный — все нули.
    pub fn preshared_key_bytes(&self) -> WireguardResult<[u8; KEY_LEN]> {
        match &self.preshared_key {
            Some(text) => decode_key(text, "предварительный ключ"),
            None => Ok([0u8; KEY_LEN]),
        }
    }

    /// Адрес IPv4 интерфейса вместе с длиной префикса.
    pub fn address_ipv4_parsed(&self) -> WireguardResult<(Ipv4Addr, u8)> {
        let (addr, prefix) = split_prefix(&self.address_ipv4, "адрес IPv4")?;
        let addr: Ipv4Addr = addr
            .parse()
            .map_err(|_| WireguardError::config(format!("`{addr}` — не адрес IPv4")))?;
        if prefix > 32 {
            return Err(WireguardError::config(format!(
                "длина префикса IPv4 {prefix} больше 32"
            )));
        }
        Ok((addr, prefix))
    }

    /// Адрес IPv6 интерфейса вместе с длиной префикса, если он задан.
    pub fn address_ipv6_parsed(&self) -> WireguardResult<Option<(Ipv6Addr, u8)>> {
        let Some(raw) = &self.address_ipv6 else {
            return Ok(None);
        };
        let (addr, prefix) = split_prefix(raw, "адрес IPv6")?;
        let addr: Ipv6Addr = addr
            .parse()
            .map_err(|_| WireguardError::config(format!("`{addr}` — не адрес IPv6")))?;
        if prefix > 128 {
            return Err(WireguardError::config(format!(
                "длина префикса IPv6 {prefix} больше 128"
            )));
        }
        Ok(Some((addr, prefix)))
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> WireguardResult<()> {
        self.private_key_bytes()?;
        self.server_public_key_bytes()?;
        self.preshared_key_bytes()?;
        self.address_ipv4_parsed()?;
        self.address_ipv6_parsed()?;

        if self.mtu == 0 || self.mtu > 1500 {
            return Err(WireguardError::config(format!(
                "MTU {} вне разумных пределов: от 1 до 1500",
                self.mtu
            )));
        }
        if self.keepalive_secs > MAX_KEEPALIVE_SECS {
            return Err(WireguardError::config(format!(
                "keepalive {} больше предела в {MAX_KEEPALIVE_SECS} секунд",
                self.keepalive_secs
            )));
        }
        Ok(())
    }
}

/// Разбирает base64-ключ ровно нужной длины.
fn decode_key(text: &str, what: &'static str) -> WireguardResult<[u8; KEY_LEN]> {
    let bytes = base64::decode_exact(text, KEY_LEN, what)
        .map_err(|e| WireguardError::config(e.to_string()))?;
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Делит запись `адрес/префикс` на составляющие.
fn split_prefix<'a>(raw: &'a str, what: &'static str) -> WireguardResult<(&'a str, u8)> {
    let (addr, prefix) = raw.split_once('/').ok_or_else(|| {
        WireguardError::config(format!("{what} `{raw}`: нужен вид адрес/префикс"))
    })?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| WireguardError::config(format!("{what} `{raw}`: длина префикса не число")))?;
    Ok((addr, prefix))
}

// Ключи не должны попасть в журнал ни целиком, ни частями (`AGENTS.md` §5.2).
impl std::fmt::Debug for WireguardConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireguardConfig")
            .field("server", &self.server)
            .field("private_key", &"<скрыт>")
            .field("server_public_key", &"<скрыт>")
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "<скрыт>"),
            )
            .field("address_ipv4", &self.address_ipv4)
            .field("address_ipv6", &self.address_ipv6)
            .field("mtu", &self.mtu)
            .field("keepalive_secs", &self.keepalive_secs)
            .field("reserved", &self.reserved)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 32 нулевых байта в base64 — сгодится для полей, где важна только
    /// длина, не значение.
    const ZERO_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn config() -> WireguardConfig {
        WireguardConfig {
            server: "vpn.example.com:51820".parse().expect("разбирается"),
            private_key: ZERO_KEY.to_owned(),
            server_public_key: ZERO_KEY.to_owned(),
            address_ipv4: "10.0.0.2/32".to_owned(),
            ..WireguardConfig::default()
        }
    }

    #[test]
    fn a_well_formed_config_validates() {
        config().validate().expect("настройки верны");
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        let short = WireguardConfig {
            private_key: "AAAA".to_owned(),
            ..config()
        };
        assert!(short.validate().is_err());
    }

    #[test]
    fn an_interface_address_without_a_prefix_is_refused() {
        let config = WireguardConfig {
            address_ipv4: "10.0.0.2".to_owned(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_ipv4_prefix_longer_than_thirty_two_is_refused() {
        let config = WireguardConfig {
            address_ipv4: "10.0.0.2/33".to_owned(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_optional_ipv6_address_is_parsed_when_present() {
        let config = WireguardConfig {
            address_ipv6: Some("fd00::2/128".to_owned()),
            ..config()
        };
        let (addr, prefix) = config
            .address_ipv6_parsed()
            .expect("разбирается")
            .expect("задан");
        assert_eq!(prefix, 128);
        assert!(addr.is_unique_local() || !addr.is_unspecified());
    }

    #[test]
    fn no_ipv6_address_is_not_an_error() {
        assert!(
            config()
                .address_ipv6_parsed()
                .expect("разбирается")
                .is_none()
        );
    }

    #[test]
    fn an_mtu_above_the_outer_path_is_refused() {
        let config = WireguardConfig {
            mtu: 1501,
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_zero_mtu_is_refused() {
        let config = WireguardConfig { mtu: 0, ..config() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_keepalive_of_zero_means_disabled_and_is_not_an_error() {
        let config = WireguardConfig {
            keepalive_secs: 0,
            ..config()
        };
        config.validate().expect("выключенный keepalive допустим");
    }

    #[test]
    fn a_keepalive_past_the_protocol_limit_is_refused() {
        let config = WireguardConfig {
            keepalive_secs: MAX_KEEPALIVE_SECS + 1,
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_missing_preshared_key_decodes_to_all_zeros() {
        // Обычное поведение `wg(8)`, а не заглушка этого крейта.
        assert_eq!(
            config().preshared_key_bytes().expect("разбирается"),
            [0u8; KEY_LEN]
        );
    }

    #[test]
    fn the_defaults_are_the_same_whether_they_come_from_code_or_from_a_file() {
        let params = json!({
            "server": "vpn.example.com:51820",
            "private_key": ZERO_KEY,
            "server_public_key": ZERO_KEY,
            "address_ipv4": "10.0.0.2/32",
        });
        let parsed: WireguardConfig = serde_json::from_value(params).expect("разбирается");
        let built = WireguardConfig::default();
        assert_eq!(parsed.mtu, built.mtu);
        assert_eq!(parsed.keepalive_secs, built.keepalive_secs);
        assert_eq!(parsed.reserved, built.reserved);
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let params = json!({
            "server": "vpn.example.com:51820",
            "private_key": ZERO_KEY,
            "server_public_key": ZERO_KEY,
            "address_ipv4": "10.0.0.2/32",
            "publik_key": "опечатка",
        });
        assert!(serde_json::from_value::<WireguardConfig>(params).is_err());
    }

    #[test]
    fn neither_key_ever_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains(ZERO_KEY), "{shown}");
    }
}
