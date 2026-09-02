//! Апстрим-резолверы.
//!
//! Кому клиент отдаёт запрос, который надо разрешить по-настоящему.
//!
//! | Способ | Виден провайдеру | Когда нужен |
//! |---|---|---|
//! | [`udp`] | целиком | загрузочное разрешение, и разрешение **через тоннель** |
//! | [`dot`] | нет | загрузочное разрешение, когда имя сервера прятать нужно |
//! | [`system`] | целиком | пока клиент не вмешивается в разрешение имён |
//!
//! Важная тонкость про UDP: в режиме `resolve` запрос идёт **внутри
//! тоннеля**, и открытый UDP там ничего не раскрывает — наружу он выходит с
//! той стороны. Шифровать имеет смысл ровно то, что идёт мимо тоннеля, то
//! есть загрузочное разрешение.

pub mod doh;
pub mod dot;
pub mod system;
pub mod udp;

use std::sync::Arc;

use async_trait::async_trait;

use crate::config::Upstream as UpstreamConfig;
use crate::error::DnsResult;

/// Куда отправить запрос и откуда получить ответ.
///
/// Работает с готовыми сообщениями DNS, а не с именами: перехваченный у
/// приложения запрос уходит апстриму как есть, со своими флагами и
/// расширениями. Разбирать и пересобирать его значило бы терять то, чего мы
/// не поняли.
#[async_trait]
pub trait Upstream: Send + Sync + 'static {
    /// Описание для журнала и диагностики.
    fn describe(&self) -> String;

    /// Отправляет запрос и ждёт ответ.
    async fn query(&self, request: &[u8]) -> DnsResult<Vec<u8>>;
}

/// Собирает апстрим по настройкам.
pub fn build(config: &UpstreamConfig) -> DnsResult<Arc<dyn Upstream>> {
    match config {
        UpstreamConfig::Udp { address } => Ok(Arc::new(udp::UdpUpstream::parse(address)?)),
        UpstreamConfig::Tls {
            address,
            server_name,
        } => Ok(Arc::new(dot::DotUpstream::new(address, server_name)?)),
        UpstreamConfig::Https { url } => Ok(Arc::new(doh::DohUpstream::new(url)?)),
    }
}

/// Собирает список апстримов.
///
/// Ошибка в одном не отменяет остальных: список — это запасные пути друг для
/// друга, и отказ поднимать клиент из-за одной опечатки был бы чрезмерным.
/// Но пустой список — уже ошибка: разрешать имена станет некому.
pub fn build_all(configs: &[UpstreamConfig]) -> DnsResult<Vec<Arc<dyn Upstream>>> {
    let mut upstreams = Vec::new();

    for config in configs {
        match build(config) {
            Ok(upstream) => upstreams.push(upstream),
            Err(err) => tracing::warn!(%err, "апстрим DNS пропущен"),
        }
    }

    if upstreams.is_empty() {
        return Err(crate::error::DnsError::Config(
            "не удалось собрать ни одного апстрима DNS".to_owned(),
        ));
    }
    Ok(upstreams)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_udp_and_tls() {
        let udp = build(&UpstreamConfig::Udp {
            address: "1.1.1.1:53".to_owned(),
        })
        .expect("собирается");
        assert!(udp.describe().starts_with("udp://"));

        let tls = build(&UpstreamConfig::Tls {
            address: "1.1.1.1".to_owned(),
            server_name: "cloudflare-dns.com".to_owned(),
        })
        .expect("собирается");
        assert!(tls.describe().starts_with("tls://"));
    }

    #[test]
    fn a_broken_entry_does_not_kill_the_list() {
        // Опечатка в одном апстриме не повод отказаться поднимать клиент:
        // остальные продолжают работать.
        let upstreams = build_all(&[
            UpstreamConfig::Udp {
                address: "не адрес".to_owned(),
            },
            UpstreamConfig::Udp {
                address: "8.8.8.8".to_owned(),
            },
        ])
        .expect("список собирается");
        assert_eq!(upstreams.len(), 1);
    }

    #[test]
    fn an_empty_list_is_an_error() {
        // Разрешать имена станет некому — молчать об этом нельзя.
        assert!(build_all(&[]).is_err());
        assert!(
            build_all(&[UpstreamConfig::Udp {
                address: "мусор".to_owned()
            }])
            .is_err()
        );
    }
}
