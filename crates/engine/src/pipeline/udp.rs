//! UDP: сессия на сокет приложения, умирает от тишины.
//!
//! Назначение у каждой датаграммы своё; запросы к порту 53 обслуживает
//! перехват DNS и наружу не уходят.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use parking_lot::RwLock;
use penguin_core::address::{Address, SocketAddress};
use penguin_core::network::Network;
use penguin_dns::FakeIpMap;
use penguin_dns::hijack::DnsHijacker;
use penguin_inbound::inbound::{InboundHandler, InboundRequest};
use penguin_netstack::Datagram;
use penguin_proto::datagram::ProxyDatagram;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::pipeline::Pipeline;

/// Порт, на котором работает DNS.
pub const DNS_PORT: u16 = 53;

/// Сколько сессия живёт без единой датаграммы.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Наибольшая датаграмма, которую имеет смысл принимать.
pub const MAX_DATAGRAM: usize = 65_535;

/// Ключ сессии: сокет приложения (без назначения).
type SessionKey = std::net::SocketAddr;

type Sessions = Arc<RwLock<HashMap<SessionKey, Arc<dyn ProxyDatagram>>>>;

/// Обслуживает UDP из тоннеля.
pub async fn pump(
    mut incoming: mpsc::Receiver<Datagram>,
    outgoing: mpsc::Sender<Datagram>,
    pipeline: Arc<Pipeline>,
    dns: Option<Arc<DnsHijacker>>,
    fake_ip: Option<Arc<FakeIpMap>>,
    cancel: CancellationToken,
) {
    let sessions = Sessions::default();

    loop {
        let datagram = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            datagram = incoming.recv() => datagram,
        };

        let Some(datagram) = datagram else { break };

        if datagram.destination.port() == DNS_PORT
            && let Some(hijacker) = &dns
        {
            spawn_dns_answer(Arc::clone(hijacker), datagram, outgoing.clone());
            continue;
        }

        let Some(session) = session_for(&sessions, &datagram, &pipeline, &outgoing, &cancel).await
        else {
            continue;
        };

        let target = resolve_target(datagram.destination, fake_ip.as_ref());
        if let Err(err) = session.send_to(datagram.payload, &target).await {
            tracing::debug!(%target, %err, "датаграмма не отправлена");
            sessions.write().remove(&datagram.source);
        }
    }

    sessions.write().clear();
}

/// Отвечает на запрос DNS, не выпуская его наружу.
fn spawn_dns_answer(
    hijacker: Arc<DnsHijacker>,
    datagram: Datagram,
    outgoing: mpsc::Sender<Datagram>,
) {
    tokio::spawn(async move {
        match hijacker.handle(&datagram.payload).await {
            Ok(response) => {
                let answer = Datagram {
                    source: datagram.source,
                    destination: datagram.destination,
                    payload: Bytes::from(response),
                };
                let _ = outgoing.send(answer).await;
            }
            Err(err) => tracing::debug!(%err, "запрос DNS не обслужен"),
        }
    });
}

/// Находит или открывает канал наружу для этого сокета приложения.
async fn session_for(
    sessions: &Sessions,
    datagram: &Datagram,
    pipeline: &Arc<Pipeline>,
    outgoing: &mpsc::Sender<Datagram>,
    cancel: &CancellationToken,
) -> Option<Arc<dyn ProxyDatagram>> {
    if let Some(existing) = sessions.read().get(&datagram.source) {
        return Some(Arc::clone(existing));
    }

    let request = InboundRequest {
        source: datagram.source,
        target: SocketAddress::from(datagram.destination),
        network: Network::Udp,
    };

    let channel = match pipeline.open_udp(&request).await {
        Ok(channel) => Arc::<dyn ProxyDatagram>::from(channel),
        Err(err) => {
            tracing::debug!(%err, "канал UDP не открылся");
            return None;
        }
    };

    sessions
        .write()
        .insert(datagram.source, Arc::clone(&channel));
    spawn_reader(
        Arc::clone(&channel),
        datagram.source,
        outgoing.clone(),
        Arc::clone(sessions),
        cancel.clone(),
    );
    Some(channel)
}

/// Читает ответы и возвращает их приложению.
fn spawn_reader(
    channel: Arc<dyn ProxyDatagram>,
    app: SessionKey,
    outgoing: mpsc::Sender<Datagram>,
    sessions: Sessions,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            let received = tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                received = tokio::time::timeout(SESSION_TIMEOUT, channel.recv_from()) => received,
            };

            let Ok(Ok((payload, from))) = received else {
                break;
            };

            // Ответ с именем вместо адреса в IP-пакет не собрать.
            let Some(source) = from.as_socket_addr() else {
                continue;
            };

            let answer = Datagram {
                source: app,
                destination: source,
                payload,
            };
            if outgoing.send(answer).await.is_err() {
                break;
            }
        }

        sessions.write().remove(&app);
        let _ = channel.close().await;
    });
}

/// Разворачивает подставной адрес обратно в имя.
fn resolve_target(
    destination: std::net::SocketAddr,
    fake_ip: Option<&Arc<FakeIpMap>>,
) -> SocketAddress {
    if let (Some(map), std::net::IpAddr::V4(v4)) = (fake_ip, destination.ip())
        && let Some(domain) = map.domain_for(v4)
    {
        return SocketAddress::new(Address::domain(&*domain), destination.port());
    }
    SocketAddress::from(destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_is_reasonable() {
        assert!(SESSION_TIMEOUT >= Duration::from_secs(15));
        assert!(SESSION_TIMEOUT <= Duration::from_secs(120));
    }

    #[test]
    fn max_datagram_matches_the_protocol() {
        assert_eq!(MAX_DATAGRAM, u16::MAX as usize);
    }

    #[test]
    fn fake_address_becomes_a_name() {
        let map = Arc::new(FakeIpMap::new("198.18.0.0/15").expect("подсеть"));
        let address = map.address_for("dns.example").expect("адрес выдан");

        let destination = std::net::SocketAddr::new(std::net::IpAddr::V4(address), 443);
        let target = resolve_target(destination, Some(&map));
        assert_eq!(target.host.as_domain(), Some("dns.example"));
        assert_eq!(target.port, 443);
    }

    #[test]
    fn real_address_stays_an_address() {
        let map = Arc::new(FakeIpMap::new("198.18.0.0/15").expect("подсеть"));
        let destination: std::net::SocketAddr = "8.8.8.8:53".parse().expect("адрес");
        let target = resolve_target(destination, Some(&map));
        assert!(target.host.as_ip().is_some());
    }

    #[test]
    fn works_without_fake_ip() {
        let destination: std::net::SocketAddr = "8.8.8.8:53".parse().expect("адрес");
        let target = resolve_target(destination, None);
        assert_eq!(target, SocketAddress::from(destination));
    }

    #[test]
    fn session_key_is_the_application_socket() {
        let first: SessionKey = "10.0.0.2:50000".parse().expect("адрес");
        let second: SessionKey = "10.0.0.2:50001".parse().expect("адрес");
        assert_ne!(first, second);
    }
}
