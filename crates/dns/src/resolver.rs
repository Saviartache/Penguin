//! `Resolver` — трейт разрешения имён.
//!
//! **Основной** разрешатель отвечает приложениям через тоннель. **Загрузочный**
//! разрешает имя самого сервера и обязан ходить мимо тоннеля: иначе адрес
//! нужен тоннелю, а тоннель — адресу.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::error::{DnsError, DnsResult};

/// Разрешение имени в адреса.
#[async_trait]
pub trait Resolver: Send + Sync + 'static {
    /// Возвращает адреса имени; пустой список — «такого имени нет», а не сбой.
    async fn resolve(&self, host: &str) -> DnsResult<Vec<IpAddr>>;
}

/// Системное разрешение: годится, пока TUN не перехватывает трафик.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str) -> DnsResult<Vec<IpAddr>> {
        // Порт формальный: `lookup_host` принимает только пару.
        let addresses = tokio::net::lookup_host((host, 0))
            .await
            .map_err(|e| DnsError::Upstream(format!("{host}: {e}")))?
            .map(|addr| addr.ip())
            .collect();
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_numeric_host_without_network() {
        let addresses = SystemResolver
            .resolve("127.0.0.1")
            .await
            .expect("разбирается");
        assert_eq!(addresses, vec![IpAddr::from([127, 0, 0, 1])]);
    }

    #[tokio::test]
    async fn resolves_localhost() {
        let addresses = SystemResolver
            .resolve("localhost")
            .await
            .expect("разбирается");
        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(|ip| ip.is_loopback()));
    }
}
