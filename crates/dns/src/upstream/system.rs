//! Системный резолвер: годится только в режиме прокси и до подключения. Когда
//! TUN стал маршрутом по умолчанию, запрос уходит в ещё не поднятый тоннель;
//! тогда нужны [`super::udp`] или [`super::dot`].

use std::net::IpAddr;

use async_trait::async_trait;

use crate::error::{DnsError, DnsResult};
use crate::resolver::Resolver;

/// Разрешение средствами системы.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemUpstream;

#[async_trait]
impl Resolver for SystemUpstream {
    async fn resolve(&self, host: &str) -> DnsResult<Vec<IpAddr>> {
        // Порт формальный: `lookup_host` принимает только пару.
        let addresses: Vec<IpAddr> = tokio::net::lookup_host((host, 0))
            .await
            .map_err(|e| DnsError::Upstream(format!("{host}: {e}")))?
            .map(|addr| addr.ip())
            .collect();

        if addresses.is_empty() {
            return Err(DnsError::NotFound(host.to_owned()));
        }
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_a_numeric_host_without_network() {
        let addresses = SystemUpstream
            .resolve("127.0.0.1")
            .await
            .expect("разбирается");
        assert_eq!(addresses, vec![IpAddr::from([127, 0, 0, 1])]);
    }

    #[tokio::test]
    async fn missing_name_is_not_found_rather_than_empty() {
        let result = SystemUpstream
            .resolve("этого-имени-точно-нет.invalid")
            .await;
        assert!(result.is_err());
    }
}
