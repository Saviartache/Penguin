//! `Resolver` — трейт разрешения имён.
//!
//! Разрешателей в клиенте два, и путать их нельзя.
//!
//! **Основной** отвечает приложениям и работает через тоннель — так провайдер
//! не видит, какие имена спрашивает пользователь.
//!
//! **Загрузочный** (bootstrap) разрешает то, без чего тоннель не поднять:
//! прежде всего имя самого сервера. Он обязан ходить мимо тоннеля, иначе
//! получается замкнутый круг — чтобы поднять тоннель, нужен адрес сервера;
//! чтобы узнать адрес, нужен работающий тоннель.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::error::DnsResult;

/// Разрешение имени в адреса.
#[async_trait]
pub trait Resolver: Send + Sync + 'static {
    /// Возвращает адреса имени.
    ///
    /// Пустой список — не ошибка ввода-вывода, а ответ «такого имени нет»;
    /// вызывающий обязан отличать это от «не удалось спросить».
    async fn resolve(&self, host: &str) -> DnsResult<Vec<IpAddr>>;
}

/// Разрешение системными средствами.
///
/// Годится ровно там, где тоннель ещё или уже не поднят: в режиме прокси и
/// до подключения. Как только TUN перехватывает трафик, системный
/// разрешатель отправляет запрос через него — то есть в ещё не работающий
/// тоннель, — и перестаёт отвечать. Для этого случая есть
/// [`crate::upstream`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str) -> DnsResult<Vec<IpAddr>> {
        // Порт нужен только формально: `lookup_host` разбирает пару, а не
        // голое имя. Ноль ни на что не влияет.
        let addresses = tokio::net::lookup_host((host, 0))
            .await
            .map_err(|e| crate::error::DnsError::Upstream(format!("{host}: {e}")))?
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
        // Числовой адрес обязан разрешаться, даже когда сети нет вовсе.
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
