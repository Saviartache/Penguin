//! Перехват запросов к порту 53 из TUN: иначе система ходит к своим DNS мимо
//! тоннеля, а провайдер видит имена и правила по доменам не срабатывают.
//!
//! Порядок ответа: hosts, кэш, fake-IP, апстрим.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::cache::DnsCache;
use crate::config::{DnsConfig, DnsMode, FAKE_IP_TTL};
use crate::error::{DnsError, DnsResult};
use crate::fakeip::FakeIpMap;
use crate::hosts::Hosts;
use crate::message::{self, Question, RecordType};
use crate::resolver::Resolver;
use crate::upstream::{self, Upstream};

/// Обработчик перехваченных запросов.
pub struct DnsHijacker {
    mode: DnsMode,
    hosts: Hosts,
    cache: DnsCache,
    fake_ip: Option<Arc<FakeIpMap>>,
    upstreams: Vec<Arc<dyn Upstream>>,
}

impl std::fmt::Debug for DnsHijacker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsHijacker")
            .field("mode", &self.mode)
            .field("hosts", &self.hosts.len())
            .field("upstreams", &self.upstreams.len())
            .finish()
    }
}

impl DnsHijacker {
    /// Собирает обработчик по настройкам.
    pub fn new(config: &DnsConfig) -> DnsResult<Self> {
        crate::config::validate(config)?;

        let mut hosts = Hosts::from_config(&config.hosts);
        hosts.merge_system();

        let fake_ip = match config.mode {
            DnsMode::FakeIp => Some(Arc::new(FakeIpMap::new(&config.fake_ip_range)?)),
            DnsMode::Resolve | DnsMode::System => None,
        };

        let upstreams = if config.mode == DnsMode::System {
            Vec::new()
        } else {
            // Мимо набирателя: запросы приложений идут по правилам, в том числе в тоннель.
            upstream::build_all(&config.upstreams, &None)?
        };

        Ok(Self {
            mode: config.mode,
            hosts,
            cache: DnsCache::new(config.min_cache_ttl),
            fake_ip,
            upstreams,
        })
    }

    /// Соответствие подставных адресов и имён: по нему движок узнаёт имя при соединении.
    pub fn fake_ip(&self) -> Option<&Arc<FakeIpMap>> {
        self.fake_ip.as_ref()
    }

    /// Отвечает на перехваченный запрос; апстриму он уходит как есть. Подставные ответы не кэшируются.
    pub async fn handle(&self, request: &[u8]) -> DnsResult<Vec<u8>> {
        let question = message::parse_query(request)?;
        let name = question.name.as_str();
        let kind = question.record_type;

        if let Some(answer) = self.answer_from_hosts(&question)? {
            tracing::debug!(name, ?kind, "DNS: ответ из hosts");
            return Ok(answer);
        }

        if let Some(mut cached) = self.cache.get(&question.name, question.record_type) {
            message::set_id(&mut cached, question.id);
            tracing::debug!(name, ?kind, "DNS: ответ из кэша");
            return Ok(cached);
        }

        if let Some(answer) = self.answer_with_fake_ip(&question)? {
            tracing::debug!(name, ?kind, "DNS: подставной ответ");
            return Ok(answer);
        }

        let started = std::time::Instant::now();
        let response = self.ask_upstreams(request).await.inspect_err(|err| {
            tracing::debug!(name, ?kind, %err, "DNS: апстримы не ответили");
        })?;
        tracing::debug!(
            name,
            ?kind,
            ms = started.elapsed().as_millis() as u64,
            "DNS: ответ апстрима"
        );
        let ttl = message::min_ttl(&response).unwrap_or(0);
        self.cache
            .insert(&question.name, question.record_type, response.clone(), ttl);
        Ok(response)
    }

    /// Запись другого семейства даёт пустой ответ, а не уход к апстриму.
    fn answer_from_hosts(&self, question: &Question) -> DnsResult<Option<Vec<u8>>> {
        let Some(addresses) = self.hosts.lookup(&question.name) else {
            return Ok(None);
        };
        Ok(Some(message::build_answer(question, addresses, 60)?))
    }

    /// На `AAAA` — пустой успех: приложение сразу пойдёт за `A`, а отказ вызвал бы повторы.
    fn answer_with_fake_ip(&self, question: &Question) -> DnsResult<Option<Vec<u8>>> {
        let Some(map) = &self.fake_ip else {
            return Ok(None);
        };

        match question.record_type {
            RecordType::A => {
                let address = IpAddr::V4(map.address_for(&question.name)?);
                Ok(Some(message::build_answer(
                    question,
                    &[address],
                    FAKE_IP_TTL,
                )?))
            }
            RecordType::AAAA => Ok(Some(message::build_answer(question, &[], FAKE_IP_TTL)?)),
            _ => Ok(None),
        }
    }

    /// Спрашивает апстримы по очереди.
    async fn ask_upstreams(&self, request: &[u8]) -> DnsResult<Vec<u8>> {
        let mut last_error = None;

        for upstream in &self.upstreams {
            match upstream.query(request).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    tracing::debug!(upstream = upstream.describe(), %err, "апстрим не ответил");
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DnsError::Upstream("не осталось апстримов, которых можно спросить".to_owned())
        }))
    }
}

#[async_trait]
impl Resolver for DnsHijacker {
    async fn resolve(&self, host: &str) -> DnsResult<Vec<IpAddr>> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(vec![address]);
        }

        if let Some(addresses) = self.hosts.lookup(host) {
            return Ok(addresses.to_vec());
        }

        let request = message::build_query(host, RecordType::A, message::random_id())?;
        let response = self.ask_upstreams(&request).await?;
        message::extract_addresses(&response)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn config(mode: DnsMode) -> DnsConfig {
        DnsConfig {
            mode,
            ..DnsConfig::default()
        }
    }

    fn query(name: &str, record_type: RecordType) -> Vec<u8> {
        let question = Question {
            name: name.to_owned(),
            record_type,
            id: 0x4242,
        };
        message::build_answer(&question, &[], 0).expect("собирается")
    }

    #[tokio::test]
    async fn fake_ip_mode_answers_without_network() {
        let hijacker = DnsHijacker::new(&config(DnsMode::FakeIp)).expect("собирается");
        let response = hijacker
            .handle(&query("youtube.com", RecordType::A))
            .await
            .expect("ответ");

        let addresses = message::extract_addresses(&response).expect("разбирается");
        assert_eq!(addresses.len(), 1);

        let IpAddr::V4(address) = addresses[0] else {
            panic!("ожидался IPv4")
        };
        let map = hijacker.fake_ip().expect("соответствие есть");
        assert_eq!(map.domain_for(address).as_deref(), Some("youtube.com"));
    }

    #[tokio::test]
    async fn cached_answer_carries_the_id_of_the_new_query() {
        let hijacker = DnsHijacker::new(&config(DnsMode::Resolve)).expect("собирается");
        let stale = message::build_answer(
            &Question {
                name: "example.com".to_owned(),
                record_type: RecordType::A,
                id: 1,
            },
            &[IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            60,
        )
        .expect("собирается");
        hijacker
            .cache
            .insert("example.com", RecordType::A, stale, 60);

        let response = hijacker
            .handle(&query("example.com", RecordType::A))
            .await
            .expect("ответ");
        assert_eq!(&response[..2], 0x4242u16.to_be_bytes());
    }

    #[tokio::test]
    async fn same_name_gets_the_same_fake_address() {
        let hijacker = DnsHijacker::new(&config(DnsMode::FakeIp)).expect("собирается");
        let first = hijacker
            .handle(&query("example.com", RecordType::A))
            .await
            .expect("ответ");
        let second = hijacker
            .handle(&query("example.com", RecordType::A))
            .await
            .expect("ответ");
        assert_eq!(
            message::extract_addresses(&first).expect("разбирается"),
            message::extract_addresses(&second).expect("разбирается")
        );
    }

    #[tokio::test]
    async fn aaaa_gets_an_empty_success_not_a_refusal() {
        let hijacker = DnsHijacker::new(&config(DnsMode::FakeIp)).expect("собирается");
        let response = hijacker
            .handle(&query("example.com", RecordType::AAAA))
            .await
            .expect("ответ");
        assert!(
            message::extract_addresses(&response)
                .expect("разбирается")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn hosts_answer_before_everything_else() {
        let mut config = config(DnsMode::FakeIp);
        config.hosts.insert(
            "pinned.example".to_owned(),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        );

        let hijacker = DnsHijacker::new(&config).expect("собирается");
        let response = hijacker
            .handle(&query("pinned.example", RecordType::A))
            .await
            .expect("ответ");

        // Статическая запись сильнее подставного адреса.
        assert_eq!(
            message::extract_addresses(&response).expect("разбирается"),
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]
        );
    }

    #[tokio::test]
    async fn hosts_entry_of_another_family_gives_an_empty_answer() {
        let mut config = config(DnsMode::FakeIp);
        config.hosts.insert(
            "pinned.example".to_owned(),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        );

        let hijacker = DnsHijacker::new(&config).expect("собирается");
        let response = hijacker
            .handle(&query("pinned.example", RecordType::AAAA))
            .await
            .expect("ответ");
        assert!(
            message::extract_addresses(&response)
                .expect("разбирается")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn numeric_host_needs_no_resolution() {
        let hijacker = DnsHijacker::new(&config(DnsMode::FakeIp)).expect("собирается");
        let addresses = hijacker.resolve("1.2.3.4").await.expect("разбирается");
        assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn broken_config_is_refused_at_build_time() {
        let config = DnsConfig {
            fake_ip_range: "мусор".to_owned(),
            ..DnsConfig::default()
        };
        assert!(DnsHijacker::new(&config).is_err());
    }

    #[test]
    fn request_ids_are_not_predictable() {
        let ids: std::collections::HashSet<u16> = (0..64).map(|_| message::random_id()).collect();
        assert!(ids.len() > 32, "идентификаторы повторяются слишком часто");
    }
}
