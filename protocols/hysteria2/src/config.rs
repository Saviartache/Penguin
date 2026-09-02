//! Параметры: сервер, пароль, полоса, обфускация, TLS.
//!
//! Имена полей совпадают с официальным клиентом Hysteria 2 везде, где это
//! возможно: пользователь приносит конфигурацию, найденную у провайдера, и она
//! должна работать без перевода.

use std::time::Duration;

use penguin_core::address::Address;
use penguin_core::endpoint::{PortSpec, ServerEndpoint};
use serde::{Deserialize, Serialize};

use crate::error::{Hysteria2Error, Hysteria2Result};

/// Настройки подключения к серверу Hysteria 2.
///
/// `Debug` реализован вручную ниже — производный вывел бы пароль в журнал.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Config {
    /// Адрес сервера: `example.com:443` или `example.com:20000-30000`.
    ///
    /// Диапазон включает смену порта: клиент переходит с порта на порт по
    /// расписанию, и провайдер, ограничивающий скорость по пятёрке, каждый раз
    /// видит новое соединение.
    pub server: String,

    /// Пароль.
    ///
    /// В `Debug` не попадает: вывод пишется вручную ниже, и пароль в него
    /// не входит.
    #[serde(alias = "auth")]
    pub password: String,

    /// TLS.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Обфускация. Без неё соединение выглядит обычным QUIC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<ObfsConfig>,

    /// Полоса. Ради неё протокол и существует.
    #[serde(default)]
    pub bandwidth: Bandwidth,

    /// Тонкие настройки QUIC.
    #[serde(default)]
    pub quic: QuicConfig,

    /// Как часто менять порт, если задан диапазон.
    #[serde(default = "default_hop_interval")]
    pub hop_interval_secs: u64,

    /// Отправлять запрос, не дожидаясь ответа сервера.
    ///
    /// Экономит один оборот на каждое соединение, но ошибку соединения
    /// приложение узнаёт позже — уже после того, как отправило свои первые
    /// байты.
    #[serde(default)]
    pub fast_open: bool,
}

/// Как часто менять порт по умолчанию.
const fn default_hop_interval() -> u64 {
    30
}

impl Hysteria2Config {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> Hysteria2Result<ServerEndpoint> {
        let raw = self.server.trim();
        let (host, ports) = split_host_ports(raw)
            .ok_or_else(|| Hysteria2Error::config(format!("не разбирается адрес `{raw}`")))?;

        let host: Address = host
            .parse()
            .map_err(|e| Hysteria2Error::config(format!("адрес сервера `{host}`: {e}")))?;
        let ports: PortSpec = ports
            .parse()
            .map_err(|e| Hysteria2Error::config(format!("порт сервера `{ports}`: {e}")))?;

        Ok(ServerEndpoint::new(host, ports))
    }

    /// Имя, которое подставляется в TLS.
    ///
    /// Явно заданное `sni` сильнее: сервер за подменённым адресом всё равно
    /// ждёт своё имя, и без этого сертификат не сойдётся.
    ///
    /// Сервер, заданный адресом, — не ошибка. Ссылки вида
    /// `hy2://пароль@203.0.113.5:1984/?insecure=1` раздают как есть, и
    /// официальный клиент с ними работает: SNI в рукопожатие просто не
    /// попадает, а сертификат сверяется с адресом (или не сверяется вовсе,
    /// если стоит `insecure`). Отказ здесь означал бы, что рабочая ссылка не
    /// проверяется и не подключается, хотя ей ничего не мешает.
    pub fn server_name(&self) -> Hysteria2Result<String> {
        if let Some(sni) = &self.tls.sni
            && !sni.is_empty()
        {
            return Ok(sni.clone());
        }
        Ok(match self.endpoint()?.host {
            Address::Domain(domain) => domain,
            // Без скобок и здесь, и для IPv6: rustls ждёт сам адрес.
            Address::Ip(ip) => ip.to_string(),
        })
    }

    /// Промежуток между сменами порта.
    pub fn hop_interval(&self) -> Duration {
        Duration::from_secs(self.hop_interval_secs.max(1))
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> Hysteria2Result<()> {
        if self.password.is_empty() {
            return Err(Hysteria2Error::config("не задан пароль"));
        }
        let endpoint = self.endpoint()?;
        self.server_name()?;

        if endpoint.ports.is_hopping() && self.obfs.is_none() {
            // Не ошибка, но и не то, чего пользователь ждал: без обфускации
            // смена порта видна как есть и смысла почти не имеет.
            tracing::warn!("смена порта задана без обфускации — эффект будет невелик");
        }
        if let Some(ObfsConfig::Salamander { password }) = &self.obfs
            && password.is_empty()
        {
            return Err(Hysteria2Error::config("не задан пароль обфускации"));
        }
        Ok(())
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями: строка «первые
// четыре символа» — это уже утечка, если паролей у пользователя два-три.
impl std::fmt::Debug for Hysteria2Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Config")
            .field("server", &self.server)
            .field("password", &"<скрыт>")
            .field("tls", &self.tls)
            .field("obfs", &self.obfs)
            .field("bandwidth", &self.bandwidth)
            .field("quic", &self.quic)
            .field("hop_interval_secs", &self.hop_interval_secs)
            .field("fast_open", &self.fast_open)
            .finish()
    }
}

/// Разделяет `host:ports`, не путаясь в двоеточиях IPv6.
fn split_host_ports(raw: &str) -> Option<(&str, &str)> {
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        return Some((host, tail.strip_prefix(':')?));
    }
    raw.rsplit_once(':')
}

/// Настройки TLS.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Имя, подставляемое в TLS вместо адреса сервера.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,

    /// Не проверять сертификат.
    ///
    /// Снимает единственную защиту от подмены сервера. Держится отдельным
    /// полем именно затем, чтобы интерфейс мог сказать об этом вслух.
    #[serde(default)]
    pub insecure: bool,

    /// Отпечаток сертификата SHA-256 в шестнадцатеричной записи.
    ///
    /// Разумная замена `insecure` для самоподписанного сертификата: проверка
    /// остаётся, просто доверие идёт не от удостоверяющего центра.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "pinSHA256")]
    pub pin_sha256: Option<String>,

    /// Путь к своему корневому сертификату.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
}

/// Обфускация.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ObfsConfig {
    /// Salamander: соль плюс BLAKE2b-256 и XOR поверх каждого пакета QUIC.
    Salamander {
        /// Общий с сервером ключ.
        password: String,
    },
}

/// Полоса пропускания.
///
/// В этом весь смысл протокола: Brutal не подстраивается под потери, а держит
/// заданную скорость. Число берётся не с потолка — это настоящая скорость
/// канала. Завысить означает забить очередь и получить задержки; занизить —
/// не получить того, за что платишь.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bandwidth {
    /// Отдача: `100 mbps`, `50m`, число в битах в секунду.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up: Option<String>,
    /// Приём.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down: Option<String>,
}

impl Bandwidth {
    /// Отдача в битах в секунду.
    pub fn up_bps(&self) -> Hysteria2Result<Option<u64>> {
        self.up.as_deref().map(parse_bandwidth).transpose()
    }

    /// Приём в битах в секунду.
    pub fn down_bps(&self) -> Hysteria2Result<Option<u64>> {
        self.down.as_deref().map(parse_bandwidth).transpose()
    }
}

/// Разбирает запись полосы: `100 mbps`, `1gbps`, `500 kbps`, `12345`.
///
/// Приставки десятичные, а не двоичные: скорость канала продают в мегабитах
/// по миллиону, и `100 mbps` у провайдера — это ровно 100 000 000, а не
/// 104 857 600.
pub fn parse_bandwidth(raw: &str) -> Hysteria2Result<u64> {
    let raw = raw.trim().to_ascii_lowercase();
    let digits_end = raw
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(raw.len());
    let (number, unit) = raw.split_at(digits_end);

    let number: f64 = number
        .parse()
        .map_err(|_| Hysteria2Error::config(format!("не разбирается полоса `{raw}`")))?;

    let multiplier = match unit.trim() {
        "" | "bps" | "b" => 1.0,
        "kbps" | "kb" | "k" => 1e3,
        "mbps" | "mb" | "m" => 1e6,
        "gbps" | "gb" | "g" => 1e9,
        "tbps" | "tb" | "t" => 1e12,
        other => {
            return Err(Hysteria2Error::config(format!(
                "неизвестная единица полосы `{other}`; ожидается bps, kbps, mbps, gbps, tbps"
            )));
        }
    };

    Ok((number * multiplier) as u64)
}

/// Тонкие настройки QUIC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuicConfig {
    /// Сколько секунд молчания до разрыва.
    pub max_idle_timeout_secs: u64,
    /// Как часто слать пустой пакет, чтобы соединение не разорвали по тишине.
    ///
    /// Не только про тишину: NAT у провайдера забывает трансляцию за
    /// десятки секунд, и после этого ответы сервера просто некуда доставить.
    pub keep_alive_secs: u64,
    /// Окно приёма одного потока.
    pub stream_receive_window: u64,
    /// Окно приёма всего соединения.
    pub conn_receive_window: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            max_idle_timeout_secs: 30,
            keep_alive_secs: 10,
            // Умолчания эталонного клиента: 8 МБ на поток и 20 МБ на
            // соединение. Окно должно вмещать произведение полосы на задержку,
            // иначе скорость упрётся в него, а не в канал: 100 Мбит/с при
            // 200 мс — это уже 2.5 МБ в полёте.
            stream_receive_window: 8 * 1024 * 1024,
            conn_receive_window: 20 * 1024 * 1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(server: &str) -> Hysteria2Config {
        Hysteria2Config {
            server: server.to_owned(),
            password: "secret".to_owned(),
            tls: TlsConfig::default(),
            obfs: None,
            bandwidth: Bandwidth::default(),
            quic: QuicConfig::default(),
            hop_interval_secs: 30,
            fast_open: false,
        }
    }

    #[test]
    fn parses_plain_server() {
        let endpoint = config("example.com:443").endpoint().expect("разбирается");
        assert_eq!(endpoint.host.as_domain(), Some("example.com"));
        assert_eq!(endpoint.ports, PortSpec::Single(443));
        assert!(!endpoint.ports.is_hopping());
    }

    #[test]
    fn parses_port_range() {
        let endpoint = config("example.com:20000-30000")
            .endpoint()
            .expect("разбирается");
        assert!(endpoint.ports.is_hopping());
        assert_eq!(endpoint.ports.count(), 10001);
    }

    #[test]
    fn parses_ipv6_server() {
        let endpoint = config("[2001:db8::1]:443").endpoint().expect("разбирается");
        assert!(endpoint.host.as_ip().is_some_and(|ip| ip.is_ipv6()));
        assert_eq!(endpoint.ports, PortSpec::Single(443));
    }

    #[test]
    fn sni_overrides_host() {
        let mut config = config("1.2.3.4:443");
        // Без `sni` в TLS идёт сам адрес: rustls тогда не шлёт SNI вовсе.
        assert_eq!(config.server_name().expect("имя"), "1.2.3.4");
        config.tls.sni = Some("example.com".to_owned());
        assert_eq!(config.server_name().expect("имя"), "example.com");
    }

    #[test]
    fn an_ip_server_needs_no_sni() {
        // Ссылку `hy2://пароль@203.0.113.5:1984/?insecure=1` раздают как есть,
        // и отказ до подключения означал бы, что рабочий сервер не проверить.
        assert_eq!(
            config("203.0.113.5:1984").server_name().expect("имя"),
            "203.0.113.5"
        );
        config("203.0.113.5:1984").validate().expect("настройки");
        // IPv6 — без скобок: rustls ждёт сам адрес.
        assert_eq!(
            config("[2001:db8::1]:443").server_name().expect("имя"),
            "2001:db8::1"
        );
    }

    #[test]
    fn parses_bandwidth_units() {
        assert_eq!(
            parse_bandwidth("100 mbps").expect("разбирается"),
            100_000_000
        );
        assert_eq!(
            parse_bandwidth("100mbps").expect("разбирается"),
            100_000_000
        );
        assert_eq!(
            parse_bandwidth("1 gbps").expect("разбирается"),
            1_000_000_000
        );
        assert_eq!(parse_bandwidth("500kbps").expect("разбирается"), 500_000);
        assert_eq!(parse_bandwidth("12345").expect("разбирается"), 12_345);
        assert_eq!(parse_bandwidth("1.5 mbps").expect("разбирается"), 1_500_000);
    }

    #[test]
    fn rejects_unknown_bandwidth_unit() {
        assert!(parse_bandwidth("100 parrots").is_err());
        assert!(parse_bandwidth("быстро").is_err());
    }

    #[test]
    fn rejects_empty_password() {
        let mut config = config("example.com:443");
        config.password = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn debug_hides_password() {
        let rendered = format!("{:?}", config("example.com:443"));
        assert!(
            !rendered.contains("secret"),
            "пароль попал в Debug: {rendered}"
        );
        assert!(rendered.contains("<скрыт>"));
    }

    #[test]
    fn accepts_official_client_field_names() {
        // Конфигурацию приносят от провайдера как есть — она обязана
        // разобраться без перевода имён полей.
        let raw = serde_json::json!({
            "server": "example.com:443",
            "auth": "hunter2",
            "tls": { "sni": "example.com", "insecure": false },
            "obfs": { "type": "salamander", "password": "obfs-key" },
            "bandwidth": { "up": "100 mbps", "down": "200 mbps" }
        });
        let config: Hysteria2Config = serde_json::from_value(raw).expect("разбирается");
        assert_eq!(config.password, "hunter2");
        assert_eq!(
            config.bandwidth.up_bps().expect("полоса"),
            Some(100_000_000)
        );
        assert!(matches!(config.obfs, Some(ObfsConfig::Salamander { .. })));
        config.validate().expect("настройки корректны");
    }
}
