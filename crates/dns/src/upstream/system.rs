//! Системный резолвер — для запросов, которые обязаны идти мимо тоннеля.
//!
//! Годится ровно до того момента, как TUN становится маршрутом по умолчанию:
//! после этого системный резолвер отправляет запрос через тоннель — то есть
//! в тот самый тоннель, который ещё надо поднять, — и перестаёт отвечать.
//!
//! Поэтому здесь он оформлен апстримом, но применяется только в режиме
//! прокси и до подключения. Загрузочный путь при поднятом тоннеле берёт
//! [`super::udp`] или [`super::dot`] с числовым адресом сервера.

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
        // Порт формальный: `lookup_host` разбирает пару, а не голое имя.
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
        // Пустой ответ и «имени нет» — разные вещи для вызывающего: первое
        // он мог бы принять за успех.
        let result = SystemUpstream
            .resolve("этого-имени-точно-нет.invalid")
            .await;
        assert!(result.is_err());
    }
}
