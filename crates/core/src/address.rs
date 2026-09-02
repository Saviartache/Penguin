//! `Address` — домен или IP; `SocketAddress` — адрес с портом. Разбор, вывод, сравнение.
//!
//! Домен доживает до самого выхода наружу и не разрешается по дороге. Это не
//! мелочь: правило «youtube.com в тоннель» работает только там, где имя ещё
//! известно, а после разрешения от него остаётся адрес из CDN, общий с
//! десятком других сайтов. Поэтому DNS делает тот, кто в итоге открывает
//! соединение, — прокси-сервер на той стороне или прямой выход здесь.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{CoreError, CoreResult};

/// Хост назначения: имя либо адрес.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Address {
    /// Доменное имя в нижнем регистре, без завершающей точки.
    Domain(String),
    /// Числовой адрес.
    Ip(IpAddr),
}

/// Хост вместе с портом — то, что нужно, чтобы открыть соединение.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SocketAddress {
    /// Хост назначения.
    pub host: Address,
    /// Порт назначения.
    pub port: u16,
}

impl Address {
    /// Домен, приведённый к каноническому виду: нижний регистр, без точки в конце.
    ///
    /// Нормализация здесь, а не в сопоставителях: иначе одно и то же имя,
    /// пришедшее из DNS-ответа и из заголовка `Host`, не совпадёт само с собой.
    pub fn domain(name: impl AsRef<str>) -> Self {
        Self::Domain(normalize_domain(name.as_ref()))
    }

    /// Домен, если это домен.
    pub fn as_domain(&self) -> Option<&str> {
        match self {
            Self::Domain(d) => Some(d),
            Self::Ip(_) => None,
        }
    }

    /// Адрес, если это адрес.
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(*ip),
            Self::Domain(_) => None,
        }
    }

    /// Это домен.
    pub fn is_domain(&self) -> bool {
        matches!(self, Self::Domain(_))
    }
}

/// Приводит доменное имя к виду, в котором его сравнивают правила.
pub fn normalize_domain(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl SocketAddress {
    /// Собирает адрес назначения из хоста и порта.
    pub fn new(host: Address, port: u16) -> Self {
        Self { host, port }
    }

    /// Адрес назначения из домена и порта.
    pub fn domain(name: impl AsRef<str>, port: u16) -> Self {
        Self::new(Address::domain(name), port)
    }

    /// Адрес назначения из IP и порта.
    pub fn ip(ip: IpAddr, port: u16) -> Self {
        Self::new(Address::Ip(ip), port)
    }

    /// Строка `host:port` в том виде, в каком её ждут Hysteria 2 и SOCKS5.
    ///
    /// IPv6 берётся в квадратные скобки: без них `::1:443` не разбирается
    /// однозначно ни одной стороной.
    pub fn to_wire(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// `SocketAddr`, если хост числовой.
    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        self.host.as_ip().map(|ip| SocketAddr::new(ip, self.port))
    }
}

impl FromStr for Address {
    type Err = CoreError;

    fn from_str(s: &str) -> CoreResult<Self> {
        let s = s.trim();
        // Скобки вокруг IPv6 — часть записи `host:port`, а не самого адреса.
        let bare = s
            .strip_prefix('[')
            .and_then(|r| r.strip_suffix(']'))
            .unwrap_or(s);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        let domain = normalize_domain(s);
        if domain.is_empty() {
            return Err(CoreError::InvalidAddress(s.to_owned()));
        }
        Ok(Self::Domain(domain))
    }
}

impl FromStr for SocketAddress {
    type Err = CoreError;

    fn from_str(s: &str) -> CoreResult<Self> {
        let s = s.trim();
        let invalid = || CoreError::InvalidAddress(s.to_owned());

        // Порт отделяется последним двоеточием, но у IPv6 без скобок их много.
        // Поэтому сначала разбирается форма `[адрес]:порт`, и только потом —
        // всё остальное по последнему двоеточию.
        let (host_part, port_part) = if let Some(rest) = s.strip_prefix('[') {
            let (host, tail) = rest.split_once(']').ok_or_else(invalid)?;
            (host, tail.strip_prefix(':').ok_or_else(invalid)?)
        } else {
            s.rsplit_once(':').ok_or_else(invalid)?
        };

        let port: u16 = port_part.parse().map_err(|_| invalid())?;
        let host: Address = host_part.parse()?;
        Ok(Self::new(host, port))
    }
}

impl From<SocketAddr> for SocketAddress {
    fn from(addr: SocketAddr) -> Self {
        Self::new(Address::Ip(addr.ip()), addr.port())
    }
}

impl From<IpAddr> for Address {
    fn from(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(d) => f.write_str(d),
            // Скобки ставятся здесь, а не в `to_wire`: адрес выводится и сам
            // по себе, и в составе `host:port`, и разойтись эти два вывода не
            // должны.
            Self::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]"),
            Self::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_wire())
    }
}

// Адреса сериализуются строкой, а не объектом с тегом: конфигурацию правит
// человек, и `"example.com:443"` он напишет, а `{ "host": { "Domain": … } }`
// — нет.
impl Serialize for Address {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(de)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl Serialize for SocketAddress {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_wire())
    }
}

impl<'de> Deserialize<'de> for SocketAddress {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(de)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn domain_is_normalized() {
        assert_eq!(
            Address::domain("Example.COM."),
            Address::Domain("example.com".into())
        );
    }

    #[test]
    fn parses_v4_with_port() {
        let a: SocketAddress = "1.2.3.4:443".parse().expect("разбирается");
        assert_eq!(a.host.as_ip(), Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert_eq!(a.port, 443);
    }

    #[test]
    fn parses_v6_in_brackets() {
        let a: SocketAddress = "[2001:db8::1]:8443".parse().expect("разбирается");
        assert_eq!(a.port, 8443);
        assert!(a.host.as_ip().is_some_and(|ip| ip.is_ipv6()));
        // Скобки должны вернуться при выводе — иначе строка не разберётся обратно.
        assert_eq!(a.to_wire(), "[2001:db8::1]:8443");
    }

    #[test]
    fn parses_domain_with_port() {
        let a: SocketAddress = "Example.com:80".parse().expect("разбирается");
        assert_eq!(a.host.as_domain(), Some("example.com"));
    }

    #[test]
    fn round_trips_through_string() {
        for raw in ["example.com:443", "1.2.3.4:53", "[2001:db8::1]:8443"] {
            let parsed: SocketAddress = raw.parse().expect("разбирается");
            assert_eq!(parsed.to_wire(), raw);
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!("example.com".parse::<SocketAddress>().is_err());
        assert!("example.com:99999".parse::<SocketAddress>().is_err());
        assert!(":443".parse::<SocketAddress>().is_err());
    }
}
