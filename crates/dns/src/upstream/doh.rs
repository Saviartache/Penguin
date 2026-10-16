//! DNS-over-HTTPS: намеренно не реализован.
//!
//! HTTP-клиента в Penguin нет, а ради одного запроса тянуть `hyper` или второй
//! TLS-стек не стоит. Замена — [`super::dot`] с той же гарантией приватности.
//! Настройка `kind = "https"` честно отказывает, а не подменяется молча.

use async_trait::async_trait;

use super::Upstream;
use crate::error::{DnsError, DnsResult};

/// DNS поверх HTTPS.
#[derive(Debug, Clone)]
pub struct DohUpstream {
    url: String,
}

impl DohUpstream {
    /// Всегда возвращает ошибку с подсказкой заменить на DoT.
    pub fn new(url: &str) -> DnsResult<Self> {
        Err(DnsError::Config(format!(
            "DNS-over-HTTPS (`{url}`) не поддерживается; \
             используйте DNS-over-TLS: kind = \"tls\", address = \"1.1.1.1\", \
             server_name = \"cloudflare-dns.com\""
        )))
    }

    /// Адрес точки запроса.
    pub fn url(&self) -> &str {
        &self.url
    }
}

#[async_trait]
impl Upstream for DohUpstream {
    fn describe(&self) -> String {
        format!("https://{}", self.url)
    }

    async fn query(&self, _request: &[u8]) -> DnsResult<Vec<u8>> {
        Err(DnsError::Config(
            "DNS-over-HTTPS не поддерживается".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_clearly_and_says_what_to_use() {
        let err = DohUpstream::new("https://1.1.1.1/dns-query").expect_err("не поддерживается");
        let message = err.to_string();
        assert!(message.contains("не поддерживается"));
        assert!(message.contains("tls"), "не подсказана замена: {message}");
    }
}
