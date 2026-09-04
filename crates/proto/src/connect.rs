//! Как протокол добирается до своего сервера: имя в адреса, адрес в сокет.
//!
//! Свободные функции, а не метод трейта: разрешение имени и перебор адресов
//! одинаковы у всех протоколов, и заставлять каждый повторять их — верный
//! способ получить пять разных ответов на вопрос «а если у сервера два
//! адреса». Ровно по той же причине здесь живёт [`crate::probe::probe`].
//!
//! Сокеты по-прежнему выдаёт [`Dialer`]: эти функции только зовут его в
//! правильном порядке. Открыть сокет самому протокол не может и не должен —
//! см. [`crate::dialer`].

use std::net::SocketAddr;

use penguin_core::address::Address;
use tokio::net::TcpStream;

use crate::dialer::Dialer;
use crate::error::ProtocolError;

/// Адреса, по которым можно достучаться до сервера.
///
/// Имя разрешается через [`Dialer`], а не системным резолвером: системный
/// пошёл бы через TUN, то есть в ещё не поднятый тоннель.
pub async fn resolve(
    dialer: &dyn Dialer,
    host: &Address,
    port: u16,
) -> Result<Vec<SocketAddr>, ProtocolError> {
    match host {
        Address::Ip(ip) => Ok(vec![SocketAddr::new(*ip, port)]),
        Address::Domain(domain) => {
            let addresses = dialer.resolve(domain).await?;
            if addresses.is_empty() {
                return Err(ProtocolError::Connect(format!(
                    "имя `{domain}` не разрешается ни в один адрес"
                )));
            }
            Ok(addresses
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect())
        }
    }
}

/// Открывает TCP-соединение до сервера мимо тоннеля.
///
/// Адреса перебираются по порядку: у имени их бывает несколько, и первый
/// может не отвечать — так бывает у сервера с IPv6-записью в сети без IPv6.
/// Возвращается ошибка последней попытки: она и есть та, из-за которой
/// подключиться не вышло.
pub async fn dial(
    dialer: &dyn Dialer,
    host: &Address,
    port: u16,
) -> Result<TcpStream, ProtocolError> {
    let addresses = resolve(dialer, host, port).await?;
    let mut last = None;

    for addr in addresses {
        match dialer.dial_tcp(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last = Some(err),
        }
    }

    Err(last.unwrap_or_else(|| {
        ProtocolError::Connect(format!("до `{host}:{port}` не нашлось ни одного адреса"))
    }))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use async_trait::async_trait;
    use tokio::net::UdpSocket;

    use super::*;

    /// Резолвер, отвечающий заранее заданным списком.
    struct FakeDialer {
        answers: Vec<IpAddr>,
    }

    #[async_trait]
    impl Dialer for FakeDialer {
        async fn dial_tcp(&self, _addr: SocketAddr) -> Result<TcpStream, ProtocolError> {
            Err(ProtocolError::Connect("тест не открывает сокетов".into()))
        }

        async fn bind_udp(&self, _local: SocketAddr) -> Result<UdpSocket, ProtocolError> {
            Err(ProtocolError::Connect("тест не открывает сокетов".into()))
        }

        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
            Ok(self.answers.clone())
        }
    }

    fn dialer(answers: &[&str]) -> FakeDialer {
        FakeDialer {
            answers: answers
                .iter()
                .map(|raw| raw.parse().expect("адрес"))
                .collect(),
        }
    }

    #[tokio::test]
    async fn an_ip_server_is_not_resolved_at_all() {
        // Спрашивать резолвер про адрес — это лишний оборот на каждом
        // подключении и лишняя точка отказа.
        let dialer = dialer(&[]);
        let host = Address::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));

        let addresses = resolve(&dialer, &host, 1080).await.expect("адрес готов");
        assert_eq!(addresses, vec!["203.0.113.5:1080".parse().expect("адрес")]);
    }

    #[tokio::test]
    async fn every_answer_becomes_a_candidate() {
        // Первый адрес может не отвечать: так бывает у сервера с записью IPv6
        // в сети без IPv6.
        let dialer = dialer(&["203.0.113.5", "2001:db8::1"]);
        let host = Address::domain("proxy.example.com");

        let addresses = resolve(&dialer, &host, 1080).await.expect("адреса");
        assert_eq!(addresses.len(), 2);
        assert!(addresses.iter().all(|addr| addr.port() == 1080));
    }

    #[tokio::test]
    async fn an_empty_answer_is_an_error_not_an_empty_list() {
        // Пустой список выше по стеку превратился бы в «подключились, но
        // некуда»: ошибку надо назвать здесь.
        let dialer = dialer(&[]);
        let host = Address::domain("proxy.example.com");

        let err = resolve(&dialer, &host, 1080)
            .await
            .expect_err("адресов нет");
        assert!(err.to_string().contains("proxy.example.com"));
    }

    #[tokio::test]
    async fn dialing_reports_the_last_failure() {
        let dialer = dialer(&["203.0.113.5"]);
        let host = Address::domain("proxy.example.com");

        let err = dial(&dialer, &host, 1080).await.expect_err("сокетов нет");
        assert!(err.is_retryable(), "обрыв связи обязан повторяться");
    }
}
