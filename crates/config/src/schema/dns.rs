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
    /// Подсеть, из которой раздаются подставные адреса.
    ///
    /// `198.18.0.0/15` отведена под тестирование производительности сетей
    /// (RFC 2544) и в настоящем трафике не встречается — поэтому подставной
    /// адрес отсюда ни с чем не столкнётся.
    pub fake_ip_range: String,
    /// Куда уходят запросы, которые надо разрешить по-настоящему.
    pub upstreams: Vec<Upstream>,
    /// Резолверы для имён, которые обязаны разрешаться мимо тоннеля:
    /// адрес самого сервера, проверка связи, локальные имена.
    pub bootstrap: Vec<Upstream>,
    /// Перехватывать запросы к порту 53 из тоннеля.
    ///
    /// Без этого система пойдёт к своим серверам мимо клиента, и правила по
    /// доменам перестанут действовать, а запросы утекут провайдеру.
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
            // DoT, а не DoH: второй потребовал бы клиента HTTP/2 и второго
            // TLS-стека, а даёт ровно ту же гарантию — провайдер не видит,
            // какие имена спрашивают. Подробнее — в `penguin_dns::upstream`.
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
    /// Каждому имени выдаётся подставной адрес, а настоящее разрешение
    /// делает та сторона.
    ///
    /// Только так правило по домену работает и для приложения, которое
    /// разрешило имя заранее: обратное отображение возвращает домен по
    /// адресу в момент соединения.
    FakeIp,
    /// Запросы разрешаются по-настоящему и уходят апстримам.
    ///
    /// Честнее к приложениям, которые сами смотрят на полученный адрес, но
    /// правила по доменам работают только там, где имя видно в SNI.
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
