//! DNS: апстримы, fake-ip, hosts, защита от утечек.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Как клиент разрешает имена.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    /// Способ ответа на запросы приложений.
    pub mode: DnsMode,
    /// Подсеть подставных адресов (`198.18.0.0/15`, RFC 2544, в трафике не встречается).
    pub fake_ip_range: String,
    /// Куда уходят запросы, которые надо разрешить по-настоящему.
    pub upstreams: Vec<Upstream>,
    /// Резолверы для имён мимо тоннеля (адрес сервера, локальные имена).
    pub bootstrap: Vec<Upstream>,
    /// Перехватывать запросы к порту 53 (иначе правила по доменам и утечка).
    pub hijack: bool,
    /// Статические записи.
    pub hosts: BTreeMap<String, IpAddr>,
    /// Сколько секунд держать ответ в кэше сверх его TTL.
    pub min_cache_ttl: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            mode: DnsMode::FakeIp,
            fake_ip_range: "198.18.0.0/15".to_owned(),
            upstreams: vec![
                Upstream::Tls {
                    address: "1.1.1.1:853".to_owned(),
                    server_name: "cloudflare-dns.com".to_owned(),
                },
                Upstream::Tls {
                    address: "8.8.8.8:853".to_owned(),
                    server_name: "dns.google".to_owned(),
                },
            ],
            bootstrap: vec![
                Upstream::Udp {
                    address: "1.1.1.1:53".to_owned(),
                },
                Upstream::Udp {
                    address: "8.8.8.8:53".to_owned(),
                },
            ],
            hijack: true,
            hosts: BTreeMap::new(),
            min_cache_ttl: 60,
        }
    }
}

/// Способ ответа на запросы приложений.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// Подставной адрес на каждое имя; домен возвращается по адресу при соединении.
    FakeIp,
    /// Настоящее разрешение через апстримы; домен виден только в SNI.
    Resolve,
    /// Клиент в разрешение имён не вмешивается.
    System,
}

/// Куда отправлять DNS-запрос.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Upstream {
    /// Обычный DNS поверх UDP. Виден провайдеру целиком.
    Udp {
        /// Адрес с портом.
        address: String,
    },
    /// DNS поверх TLS.
    Tls {
        /// Адрес с портом.
        address: String,
        /// Имя для проверки сертификата.
        server_name: String,
    },
    /// DNS поверх HTTPS.
    Https {
        /// Полный URL точки запроса.
        url: String,
    },
}
