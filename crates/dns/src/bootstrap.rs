//! Загрузочное разрешение имён: как клиент узнаёт адрес своего сервера.
//!
//! Системный резолвер для этого не годится: перехват подменяет его ответы
//! адресами из подставной подсети (или системный DNS после аварийного
//! завершения смотрит в исчезнувший адаптер), и клиент звонит сам себе.
//! Поэтому имя спрашивается у своих апстримов (`dns.bootstrap`) мимо системы и
//! тоннеля. Система остаётся запасным путём на сетях, где публичные
//! резолверы недоступны; её ответ проверяется и подставные адреса отбрасываются.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::config::Upstream as UpstreamConfig;
use crate::error::{DnsError, DnsResult};
use crate::fakeip::FakeIpPool;
use crate::message::{self, RecordType};
use crate::resolver::{Resolver, SystemResolver};
use crate::upstream::Upstream;

/// Разрешатель имени сервера: загрузочный, а системный — только если загрузочный собрать не из чего.
///
/// Общая точка для службы, локального прокси и проверки профилей: у всех
/// троих системный резолвер может быть подменён прошлым запуском.
pub fn resolver_for(config: &crate::config::DnsConfig) -> Arc<dyn Resolver> {
    // Ошибку подсети ловит проверка настроек; без неё лишь не фильтруется запасной путь.
    let fake_ip = FakeIpPool::parse(&config.fake_ip_range).ok();

    match BootstrapResolver::from_config(&config.bootstrap) {
        Ok(bootstrap) => Arc::new(bootstrap.rejecting(fake_ip)),
        Err(err) => {
            tracing::warn!(%err, "загрузочное разрешение имён не собрано");
            Arc::new(SystemResolver)
        }
    }
}

/// Разрешение имён мимо системы и мимо тоннеля.
pub struct BootstrapResolver {
    /// Запасные пути друг для друга.
    upstreams: Vec<Arc<dyn Upstream>>,
    /// Подставная подсеть: адресам из неё в ответе системы верить нельзя.
    fake_ip: Option<FakeIpPool>,
}

impl std::fmt::Debug for BootstrapResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapResolver")
            .field("upstreams", &self.upstreams.len())
            .finish()
    }
}

impl BootstrapResolver {
    /// Собирает разрешатель по настройкам загрузочных апстримов.
    pub fn from_config(configs: &[UpstreamConfig]) -> DnsResult<Self> {
        Ok(Self {
            upstreams: crate::upstream::build_all(configs)?,
            fake_ip: None,
        })
    }

    /// Учит отвергать адреса из подсети подставных.
    pub fn rejecting(mut self, fake_ip: Option<FakeIpPool>) -> Self {
        self.fake_ip = fake_ip;
        self
    }

    /// Запасной путь: система может быть подменена нами же, поэтому подставные адреса отбрасываются.
    async fn ask_the_system(&self, host: &str) -> Vec<IpAddr> {
        let Ok(addresses) = SystemResolver.resolve(host).await else {
            return Vec::new();
        };
        addresses
            .into_iter()
            .filter(|address| !self.is_fake(*address))
            .collect()
    }

    fn is_fake(&self, address: IpAddr) -> bool {
        let (Some(pool), IpAddr::V4(v4)) = (&self.fake_ip, address) else {
            return false;
        };
        pool.contains(v4)
    }

    /// Первый ответивший апстрим и отвечает; пустой ответ обрывает обход (записи этого типа нет).
    async fn ask(&self, host: &str, record_type: RecordType) -> Vec<IpAddr> {
        let Ok(query) = message::build_query(host, record_type, message::random_id()) else {
            return Vec::new();
        };

        for upstream in &self.upstreams {
            match upstream.query(&query).await {
                Ok(answer) => match message::extract_addresses(&answer) {
                    Ok(addresses) if !addresses.is_empty() => return addresses,
                    Ok(_) => break,
                    Err(err) => tracing::debug!(%err, "загрузочный ответ не разбирается"),
                },
                Err(err) => tracing::debug!(
                    upstream = upstream.describe(),
                    %err,
                    "загрузочный апстрим не ответил"
                ),
            }
        }
        Vec::new()
    }
}

#[async_trait]
impl Resolver for BootstrapResolver {
    /// IPv6 спрашивается, только если IPv4 нет; систему зовут последней.
    async fn resolve(&self, host: &str) -> DnsResult<Vec<IpAddr>> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(vec![address]);
        }

        let mut addresses = self.ask(host, RecordType::A).await;
        if addresses.is_empty() {
            addresses = self.ask(host, RecordType::AAAA).await;
        }
        if addresses.is_empty() {
            tracing::debug!(host, "загрузочные апстримы молчат — спрашиваю систему");
            addresses = self.ask_the_system(host).await;
        }

        if addresses.is_empty() {
            return Err(DnsError::Upstream(format!(
                "адрес `{host}` не назвали ни загрузочные апстримы, ни система"
            )));
        }
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Апстрим с заранее заданным ответом.
    struct Canned(DnsResult<Vec<u8>>);

    #[async_trait]
    impl Upstream for Canned {
        fn describe(&self) -> String {
            "проба".to_owned()
        }

        async fn query(&self, _request: &[u8]) -> DnsResult<Vec<u8>> {
            match &self.0 {
                Ok(answer) => Ok(answer.clone()),
                Err(err) => Err(DnsError::Upstream(err.to_string())),
            }
        }
    }

    fn answer(host: &str, address: IpAddr) -> Vec<u8> {
        let question = message::Question {
            name: host.to_owned(),
            record_type: message::record_type_of(address),
            id: 1,
        };
        message::build_answer(&question, &[address], 60).expect("ответ собирается")
    }

    fn resolver(upstreams: Vec<Arc<dyn Upstream>>) -> BootstrapResolver {
        BootstrapResolver {
            upstreams,
            fake_ip: None,
        }
    }

    fn guarded(upstreams: Vec<Arc<dyn Upstream>>) -> BootstrapResolver {
        resolver(upstreams).rejecting(FakeIpPool::parse("198.18.0.0/15").ok())
    }

    #[tokio::test]
    async fn a_numeric_server_needs_no_lookup() {
        let addresses = resolver(Vec::new())
            .resolve("203.0.113.10")
            .await
            .expect("адрес разбирается");
        assert_eq!(
            addresses,
            ["203.0.113.10".parse::<IpAddr>().expect("адрес")]
        );
    }

    #[tokio::test]
    async fn the_name_is_asked_of_the_upstreams_not_the_system() {
        let real: IpAddr = "203.0.113.10".parse().expect("адрес");
        let resolver = resolver(vec![Arc::new(Canned(Ok(answer("example.net", real))))]);

        assert_eq!(
            resolver.resolve("example.net").await.expect("разрешилось"),
            [real]
        );
    }

    #[tokio::test]
    async fn a_silent_upstream_is_not_the_end() {
        let real: IpAddr = "203.0.113.10".parse().expect("адрес");
        let resolver = resolver(vec![
            Arc::new(Canned(Err(DnsError::Upstream("молчит".to_owned())))),
            Arc::new(Canned(Ok(answer("example.net", real)))),
        ]);

        assert_eq!(
            resolver.resolve("example.net").await.expect("разрешилось"),
            [real]
        );
    }

    #[tokio::test]
    async fn nobody_answering_is_an_error_not_an_empty_list() {
        // Заведомо несуществующее имя: система тоже не назовёт адреса.
        let resolver = guarded(vec![Arc::new(Canned(Err(DnsError::Upstream(
            "молчит".to_owned(),
        ))))]);
        assert!(resolver.resolve("такого-имени-нет.invalid").await.is_err());
    }

    #[test]
    fn a_fake_address_is_never_taken_for_an_answer() {
        let resolver = guarded(Vec::new());

        assert!(resolver.is_fake("198.18.0.13".parse().expect("адрес")));
        assert!(!resolver.is_fake("203.0.113.10".parse().expect("адрес")));
    }

    #[test]
    fn without_a_known_range_nothing_is_rejected() {
        let resolver = resolver(Vec::new());
        assert!(!resolver.is_fake("198.18.0.13".parse().expect("адрес")));
    }
}
