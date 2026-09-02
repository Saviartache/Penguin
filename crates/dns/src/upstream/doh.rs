//! DNS-over-HTTPS.
//!
//! # Состояние
//!
//! Не реализован, и это осознанное решение, а не забытый файл.
//!
//! DoH (RFC 8484) — это запрос HTTP/2 к обычному веб-серверу. Клиента HTTP в
//! Penguin нет: протоколу он не нужен, интерфейсу тоже. Ради одного запроса
//! пришлось бы притащить либо `hyper` со своей половиной экосистемы, либо
//! `hickory-resolver` с его собственным `rustls 0.21` — то есть **второй**
//! TLS-стек рядом с уже имеющимся `rustls 0.23`, который надо будет отдельно
//! обновлять при каждой уязвимости.
//!
//! # Что вместо
//!
//! [`super::dot`] — DNS-over-TLS. Он даёт ровно ту же гарантию (провайдер не
//! видит, какие имена спрашивают) и умещается в сто строк поверх уже
//! имеющегося TLS: соединение, длина двумя байтами, сообщение.
//!
//! Разница между DoH и DoT для этого клиента только в одном — DoH труднее
//! заблокировать, потому что он неотличим от обычного HTTPS. Но имена, ради
//! которых всё затевается, спрашиваются либо **через тоннель** (и тогда
//! провайдер их и так не видит), либо на загрузочном пути — и там достаточно
//! DoT.
//!
//! # Почему не молча
//!
//! Настройка `kind = "https"` в файле есть, и молча подменить её на DoT
//! нельзя: пользователь считал бы, что работает одно, а работало бы другое.
//! Поэтому здесь честный отказ с указанием, чем заменить.

use async_trait::async_trait;

use super::Upstream;
use crate::error::{DnsError, DnsResult};

/// DNS поверх HTTPS.
#[derive(Debug, Clone)]
pub struct DohUpstream {
    url: String,
}

impl DohUpstream {
    /// Создаёт апстрим.
    ///
    /// Всегда возвращает ошибку с указанием, чем заменить: см. заголовок
    /// модуля.
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
        // Молча подменить DoH на DoT нельзя: пользователь считал бы, что
        // работает одно, а работало бы другое.
        let err = DohUpstream::new("https://1.1.1.1/dns-query").expect_err("не поддерживается");
        let message = err.to_string();
        assert!(message.contains("не поддерживается"));
        assert!(message.contains("tls"), "не подсказана замена: {message}");
    }
}
