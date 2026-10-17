//! `ServerEndpoint` — хост, порт или диапазон портов (port hopping) сервера.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::address::{Address, split_host_port};
use crate::error::{CoreError, CoreResult};

/// Адрес сервера вместе с тем, по каким портам к нему стучаться.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEndpoint {
    /// Хост сервера.
    pub host: Address,
    /// Порты.
    pub ports: PortSpec,
}

/// Один порт или набор портов (port hopping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSpec {
    /// Один порт.
    Single(u16),
    /// Диапазоны и отдельные порты: `443`, `20000-30000`, `443,8443`.
    Multiple(Vec<PortRange>),
}

/// Диапазон портов, включительно с обеих сторон.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    /// Нижняя граница.
    pub start: u16,
    /// Верхняя граница.
    pub end: u16,
}

impl PortRange {
    /// Создаёт диапазон, приводя границы в порядок.
    pub fn new(a: u16, b: u16) -> Self {
        if a <= b {
            Self { start: a, end: b }
        } else {
            Self { start: b, end: a }
        }
    }

    /// Сколько портов в диапазоне.
    pub fn len(&self) -> u32 {
        u32::from(self.end - self.start) + 1
    }

    /// Диапазон пуст. Никогда: границы включительные.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Порт по смещению внутри диапазона.
    pub fn nth(&self, index: u32) -> u16 {
        self.start + (index % self.len()) as u16
    }
}

impl PortSpec {
    /// Общее число портов.
    pub fn count(&self) -> u32 {
        match self {
            Self::Single(_) => 1,
            Self::Multiple(ranges) => ranges.iter().map(PortRange::len).sum(),
        }
    }

    /// Порт по сквозному индексу (по модулю числа портов).
    pub fn nth(&self, index: u32) -> u16 {
        match self {
            Self::Single(p) => *p,
            Self::Multiple(ranges) => {
                let total = self.count().max(1);
                let mut offset = index % total;
                for range in ranges {
                    if offset < range.len() {
                        return range.nth(offset);
                    }
                    offset -= range.len();
                }
                ranges.first().map_or(0, |r| r.start)
            }
        }
    }

    /// Первый порт — им открывается соединение.
    pub fn first(&self) -> u16 {
        self.nth(0)
    }

    /// Портов больше одного, то есть смена порта имеет смысл.
    pub fn is_hopping(&self) -> bool {
        self.count() > 1
    }
}

impl ServerEndpoint {
    /// Собирает адрес сервера.
    pub fn new(host: Address, ports: PortSpec) -> Self {
        Self { host, ports }
    }
}

impl FromStr for ServerEndpoint {
    type Err = CoreError;

    /// Разбирает `example.com:443`, `[2001:db8::1]:443`, `example.com:20000-30000`.
    fn from_str(s: &str) -> CoreResult<Self> {
        let raw = s.trim();
        // Порта нет — умолчание не подставляется.
        let (host, ports) =
            split_host_port(raw).ok_or_else(|| CoreError::InvalidAddress(raw.to_owned()))?;
        Ok(Self::new(host.parse()?, ports.parse()?))
    }
}

impl FromStr for PortSpec {
    type Err = CoreError;

    /// Разбирает `443`, `20000-30000`, `443,8443,20000-30000`.
    fn from_str(s: &str) -> CoreResult<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(CoreError::InvalidPort(s.to_owned()));
        }

        let mut ranges = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            // Hysteria пишет диапазон и через дефис, и через двоеточие.
            let split = part.split_once('-').or_else(|| part.split_once(':'));
            let range = match split {
                Some((a, b)) => {
                    let a = a
                        .trim()
                        .parse()
                        .map_err(|_| CoreError::InvalidPort(part.to_owned()))?;
                    let b = b
                        .trim()
                        .parse()
                        .map_err(|_| CoreError::InvalidPort(part.to_owned()))?;
                    PortRange::new(a, b)
                }
                None => {
                    let p = part
                        .parse()
                        .map_err(|_| CoreError::InvalidPort(part.to_owned()))?;
                    PortRange::new(p, p)
                }
            };
            ranges.push(range);
        }

        match ranges.as_slice() {
            [] => Err(CoreError::InvalidPort(s.to_owned())),
            [one] if one.start == one.end => Ok(Self::Single(one.start)),
            _ => Ok(Self::Multiple(ranges)),
        }
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(p) => write!(f, "{p}"),
            Self::Multiple(ranges) => {
                let parts: Vec<String> = ranges
                    .iter()
                    .map(|r| {
                        if r.start == r.end {
                            r.start.to_string()
                        } else {
                            format!("{}-{}", r.start, r.end)
                        }
                    })
                    .collect();
                f.write_str(&parts.join(","))
            }
        }
    }
}

impl fmt::Display for ServerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.ports)
    }
}

impl Serialize for PortSpec {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PortSpec {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Number(u16),
            Text(String),
        }

        match Raw::deserialize(de)? {
            Raw::Number(p) => Ok(Self::Single(p)),
            Raw::Text(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_port() {
        assert_eq!(
            "443".parse::<PortSpec>().expect("разбирается"),
            PortSpec::Single(443)
        );
    }

    #[test]
    fn parses_range_with_either_separator() {
        let a = "20000-30000".parse::<PortSpec>().expect("разбирается");
        let b = "20000:30000".parse::<PortSpec>().expect("разбирается");
        assert_eq!(a, b);
        assert_eq!(a.count(), 10001);
    }

    #[test]
    fn walks_across_ranges() {
        let spec = "443,8443,9000-9002"
            .parse::<PortSpec>()
            .expect("разбирается");
        assert_eq!(spec.count(), 5);
        let walked: Vec<u16> = (0..5).map(|i| spec.nth(i)).collect();
        assert_eq!(walked, vec![443, 8443, 9000, 9001, 9002]);
        assert_eq!(spec.nth(5), 443);
    }

    #[test]
    fn round_trips_through_string() {
        for raw in ["443", "443,8443", "20000-30000"] {
            let parsed: PortSpec = raw.parse().expect("разбирается");
            assert_eq!(parsed.to_string(), raw);
        }
    }

    #[test]
    fn parses_an_endpoint_in_every_notation() {
        let endpoint: ServerEndpoint = "example.com:443".parse().expect("разбирается");
        assert_eq!(endpoint.host.as_domain(), Some("example.com"));
        assert_eq!(endpoint.ports, PortSpec::Single(443));

        let endpoint: ServerEndpoint = "1.2.3.4:1080".parse().expect("разбирается");
        assert!(endpoint.host.as_ip().is_some());

        let endpoint: ServerEndpoint = "[2001:db8::1]:443".parse().expect("разбирается");
        assert!(endpoint.host.as_ip().is_some_and(|ip| ip.is_ipv6()));
        assert_eq!(endpoint.ports, PortSpec::Single(443));

        let endpoint: ServerEndpoint = "example.com:20000-30000".parse().expect("разбирается");
        assert!(endpoint.ports.is_hopping());
    }

    #[test]
    fn a_v6_endpoint_keeps_brackets_and_hopping_ports() {
        let endpoint: ServerEndpoint = "[::1]:443,20000-30000".parse().expect("разбирается");
        assert!(endpoint.ports.is_hopping());
        assert_eq!(endpoint.to_string(), "[::1]:443,20000-30000");

        let endpoint: ServerEndpoint = "[2001:db8::1]:20000-30000".parse().expect("разбирается");
        assert_eq!(endpoint.to_string(), "[2001:db8::1]:20000-30000");
    }

    #[test]
    fn a_bare_v6_is_not_split_into_a_host_and_a_port() {
        assert!("2001:db8::1".parse::<ServerEndpoint>().is_err());
        assert!("2001:db8::1:443".parse::<ServerEndpoint>().is_err());
        assert!("fe80::1%en0".parse::<ServerEndpoint>().is_err());
        assert!("[fe80::1%en0]:443".parse::<ServerEndpoint>().is_err());
    }

    #[test]
    fn an_endpoint_without_a_port_is_refused() {
        assert!("example.com".parse::<ServerEndpoint>().is_err());
        assert!("[2001:db8::1]".parse::<ServerEndpoint>().is_err());
        assert!("example.com:абв".parse::<ServerEndpoint>().is_err());
        assert!(":443".parse::<ServerEndpoint>().is_err());
    }
}
