//! Апстрим-резолверы: [`udp`] (в режиме `resolve` идёт внутри тоннеля),
//! [`dot`] и [`doh`] (шифруют загрузочное разрешение мимо тоннеля), [`system`].

pub mod doh;
pub mod dot;
pub mod system;
pub mod udp;

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;

use crate::config::Upstream as UpstreamConfig;
use crate::error::{DnsError, DnsResult};

/// Откуда апстрим берёт сокеты: `None` — обычные, по таблице маршрутов (при поднятом
/// тоннеле — в него же).
pub type Sockets = Option<Arc<dyn Dialer>>;

fn socket_error(err: ProtocolError) -> DnsError {
    DnsError::Upstream(format!("сокет: {err}"))
}

/// Куда отправить запрос и откуда получить ответ.
///
/// Работает с готовыми сообщениями: запрос приложения уходит как есть, с флагами и расширениями.
#[async_trait]
pub trait Upstream: Send + Sync + 'static {
    /// Описание для журнала и диагностики.
    fn describe(&self) -> String;

    /// Отправляет запрос и ждёт ответ.
    async fn query(&self, request: &[u8]) -> DnsResult<Vec<u8>>;
}

/// Собирает апстрим по настройкам.
pub fn build(config: &UpstreamConfig, sockets: &Sockets) -> DnsResult<Arc<dyn Upstream>> {
    match config {
        UpstreamConfig::Udp { address } => {
            let upstream = udp::UdpUpstream::parse(address)?;
            Ok(match sockets {
                Some(sockets) => Arc::new(upstream.through(Arc::clone(sockets))),
                None => Arc::new(upstream),
            })
        }
        UpstreamConfig::Tls {
            address,
            server_name,
        } => {
            let upstream = dot::DotUpstream::new(address, server_name)?;
            Ok(match sockets {
                Some(sockets) => Arc::new(upstream.through(Arc::clone(sockets))),
                None => Arc::new(upstream),
            })
        }
        UpstreamConfig::Https { url } => Ok(Arc::new(doh::DohUpstream::new(url)?)),
    }
}

/// Собирает список апстримов.
///
/// Негодный элемент пропускается; пустой итог — ошибка.
pub fn build_all(
    configs: &[UpstreamConfig],
    sockets: &Sockets,
) -> DnsResult<Vec<Arc<dyn Upstream>>> {
    let mut upstreams = Vec::new();

    for config in configs {
        match build(config, sockets) {
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
        let udp = build(
            &UpstreamConfig::Udp {
                address: "1.1.1.1:53".to_owned(),
            },
            &None,
        )
        .expect("собирается");
        assert!(udp.describe().starts_with("udp://"));

        let tls = build(
            &UpstreamConfig::Tls {
                address: "1.1.1.1".to_owned(),
                server_name: "cloudflare-dns.com".to_owned(),
            },
            &None,
        )
        .expect("собирается");
        assert!(tls.describe().starts_with("tls://"));
    }

    #[test]
    fn a_broken_entry_does_not_kill_the_list() {
        let upstreams = build_all(
            &[
                UpstreamConfig::Udp {
                    address: "не адрес".to_owned(),
                },
                UpstreamConfig::Udp {
                    address: "8.8.8.8".to_owned(),
                },
            ],
            &None,
        )
        .expect("список собирается");
        assert_eq!(upstreams.len(), 1);
    }

    #[test]
    fn an_empty_list_is_an_error() {
        assert!(build_all(&[], &None).is_err());
        assert!(
            build_all(
                &[UpstreamConfig::Udp {
                    address: "мусор".to_owned()
                }],
                &None,
            )
            .is_err()
        );
    }
}
