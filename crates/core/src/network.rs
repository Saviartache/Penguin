//! `Network` (TCP/UDP) и `IpFamily` — из чего состоит «вид трафика».

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

/// Транспортный протокол соединения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Поток с установлением соединения.
    Tcp,
    /// Датаграммы без установления соединения.
    Udp,
}

/// Версия протокола сети.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpFamily {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl Network {
    /// Короткое имя для журнала и правил в конфигурации.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl IpFamily {
    /// Семейство адреса.
    pub const fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }

    /// Короткое имя для правил в конфигурации.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }
}

impl FromStr for Network {
    type Err = CoreError;

    fn from_str(s: &str) -> CoreResult<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(CoreError::OutOfRange {
                field: "network",
                expected: "tcp | udp",
                got: other.to_owned(),
            }),
        }
    }
}

impl FromStr for IpFamily {
    type Err = CoreError;

    fn from_str(s: &str) -> CoreResult<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "v4" | "ipv4" | "4" => Ok(Self::V4),
            "v6" | "ipv6" | "6" => Ok(Self::V6),
            other => Err(CoreError::OutOfRange {
                field: "ip_version",
                expected: "v4 | v6",
                got: other.to_owned(),
            }),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for IpFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
