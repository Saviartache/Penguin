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

/// Сколько датаграмм ждёт сессию, пока она открывается или отправляет предыдущие.
const SESSION_QUEUE: usize = 256;

/// Ключ сессии: сокет приложения (без назначения).
type SessionKey = std::net::SocketAddr;

/// Датаграмма приложения к отправке наружу.
type Outgoing = (Bytes, SocketAddress);

/// Очередь каждой сессии: насос в неё только кладёт и никого не ждёт.
type Sessions = Arc<RwLock<HashMap<SessionKey, mpsc::Sender<Outgoing>>>>;

/// Общее для насоса и его сессий.
#[derive(Clone)]
struct Shared {
    sessions: Sessions,
    pipeline: Arc<Pipeline>,
    /// Куда уходят ответы приложениям.
    outgoing: mpsc::Sender<Datagram>,
}

/// Обслуживает UDP из тоннеля.
///
/// Насос не ждёт ни открытия канала, ни отправки: и то и другое может разрешать имя или
/// поднимать соединение с сервером, а одна такая датаграмма иначе останавливала бы
/// весь UDP, включая ответы DNS.
pub async fn pump(
    mut incoming: mpsc::Receiver<Datagram>,
    outgoing: mpsc::Sender<Datagram>,
    pipeline: Arc<Pipeline>,
    dns: Option<Arc<DnsHijacker>>,
    fake_ip: Option<Arc<FakeIpMap>>,
    cancel: CancellationToken,
) {
    let shared = Shared {
        sessions: Sessions::default(),
        pipeline,
        outgoing,
    };

    loop {
        let datagram = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            datagram = incoming.recv() => datagram,
        };

        let Some(datagram) = datagram else { break };

        if !leaves_the_link(datagram.destination.ip()) {
            continue;
        }

        if datagram.destination.port() == DNS_PORT
            && let Some(hijacker) = &dns
        {
            spawn_dns_answer(Arc::clone(hijacker), datagram, shared.outgoing.clone());
            continue;
        }

        let target = resolve_target(datagram.destination, fake_ip.as_ref());
        tracing::trace!(
            source = %datagram.source,
            %target,
            bytes = datagram.payload.len(),
            "датаграмма приложения"
        );
        let queue = session_for(&shared, &datagram, &cancel);
        if queue.try_send((datagram.payload, target)).is_err() {
            tracing::debug!(source = %datagram.source, "очередь сессии UDP полна, датаграмма отброшена");
        }
    }

    shared.sessions.write().clear();
}

/// Мультикаст и широковещание (mDNS, LLMNR, SSDP) живут в своём сегменте: выпущенные
/// наружу, они возвращаются системой в тоннель и крутятся по кругу.
fn leaves_the_link(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => !(v4.is_multicast() || v4.is_broadcast()),
        std::net::IpAddr::V6(v6) => !v6.is_multicast(),
    }
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
                if outgoing.send(answer).await.is_err() {
                    tracing::debug!("ответ DNS не ушёл: стек остановлен");
                }
            }
            Err(err) => tracing::debug!(app = %datagram.source, %err, "запрос DNS не обслужен"),
        }
    });
}

/// Очередь сессии этого сокета приложения; новой сессии открывается своя задача.
fn session_for(
    shared: &Shared,
    datagram: &Datagram,
    cancel: &CancellationToken,
) -> mpsc::Sender<Outgoing> {
    if let Some(existing) = shared.sessions.read().get(&datagram.source)
        && !existing.is_closed()
    {
        return existing.clone();
    }

    let (queue, datagrams) = mpsc::channel(SESSION_QUEUE);
    shared
        .sessions
        .write()
        .insert(datagram.source, queue.clone());

    let request = InboundRequest {
        source: datagram.source,
        target: SocketAddress::from(datagram.destination),
        sniffed: None,
        network: Network::Udp,
    };
    tokio::spawn(run_session(
        request,
        datagrams,
        queue.downgrade(),
        shared.clone(),
        cancel.child_token(),
    ));
    queue
}

/// Открывает канал наружу и отправляет в него очередь сессии до её конца.
async fn run_session(
    request: InboundRequest,
    mut datagrams: mpsc::Receiver<Outgoing>,
    queue: mpsc::WeakSender<Outgoing>,
    shared: Shared,
    done: CancellationToken,
) {
    let app = request.source;
    let channel = match shared.pipeline.open_udp(&request).await {
        Ok(channel) => Arc::<dyn ProxyDatagram>::from(channel),
        Err(err) => {
            tracing::debug!(%app, target = %request.target, %err, "канал UDP не открылся");
            forget(&shared.sessions, app, &queue);
            return;
        }
    };
    tracing::debug!(%app, target = %request.target, "сессия UDP открыта");

    tokio::spawn(read_answers(
        Arc::clone(&channel),
        app,
        shared.outgoing.clone(),
        done.clone(),
    ));

    loop {
        let next = tokio::select! {
            biased;
            () = done.cancelled() => break,
            next = datagrams.recv() => next,
        };
        let Some((payload, target)) = next else { break };

        if let Err(err) = channel.send_to(payload, &target).await {
            tracing::debug!(%app, %target, %err, "датаграмма не отправлена");
            break;
        }
    }

    done.cancel();
    forget(&shared.sessions, app, &queue);
    let _ = channel.close().await;
    tracing::debug!(%app, "сессия UDP закрыта");
}

/// Убирает сессию из таблицы, если там всё ещё она, а не открытая после неё.
fn forget(sessions: &Sessions, app: SessionKey, queue: &mpsc::WeakSender<Outgoing>) {
    let mut sessions = sessions.write();
    if let (Some(current), Some(mine)) = (sessions.get(&app), queue.upgrade())
        && current.same_channel(&mine)
    {
        sessions.remove(&app);
    }
}

/// Читает ответы и возвращает их приложению; тишина дольше [`SESSION_TIMEOUT`] закрывает
/// сессию.
async fn read_answers(
    channel: Arc<dyn ProxyDatagram>,
    app: SessionKey,
    outgoing: mpsc::Sender<Datagram>,
    done: CancellationToken,
) {
    loop {
        let received = tokio::select! {
            biased;
            () = done.cancelled() => break,
            received = tokio::time::timeout(SESSION_TIMEOUT, channel.recv_from()) => received,
        };

        let (payload, from) = match received {
            Ok(Ok(answer)) => answer,
            Ok(Err(err)) => {
                tracing::debug!(%app, %err, "ответ UDP не прочитан");
                break;
            }
            Err(_) => {
                tracing::trace!(%app, "сессия UDP затихла");
                break;
            }
        };

        // Ответ с именем вместо адреса в IP-пакет не собрать.
        let Some(source) = from.as_socket_addr() else {
            continue;
        };

        tracing::trace!(%app, from = %source, bytes = payload.len(), "ответ UDP");
        let answer = Datagram {
            source: app,
            destination: source,
            payload,
        };
        if outgoing.send(answer).await.is_err() {
            break;
        }
    }

    done.cancel();
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
    fn multicast_and_broadcast_stay_in_the_segment() {
        for local in [
            "224.0.0.251",
            "224.0.0.252",
            "239.255.255.250",
            "255.255.255.255",
            "ff02::fb",
        ] {
            assert!(!leaves_the_link(local.parse().expect("адрес")), "{local}");
        }
        for remote in ["1.1.1.1", "192.168.1.1", "2606:4700::1111"] {
            assert!(leaves_the_link(remote.parse().expect("адрес")), "{remote}");
        }
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

    #[tokio::test]
    async fn a_slow_session_does_not_hold_up_dns() {
        use penguin_config::schema::routing::TunnelMode;
        use penguin_core::id::OutboundId;
        use penguin_dns::DnsConfig;
        use penguin_dns::message::{self, RecordType};
        use penguin_process::resolver::NoResolver;
        use penguin_router::engine::Router;

        use crate::direct::SystemDialer;
        use crate::metrics::counters::Metrics;
        use crate::outbounds::OutboundPool;

        /// Разрешатель, который не отвечает никогда.
        struct Silent;

        #[async_trait::async_trait]
        impl penguin_dns::Resolver for Silent {
            async fn resolve(&self, _host: &str) -> penguin_dns::DnsResult<Vec<std::net::IpAddr>> {
                std::future::pending().await
            }
        }

        let dialer = Arc::new(SystemDialer::new(Arc::new(Silent)));
        let pipeline = Arc::new(Pipeline::new(
            Arc::new(Router::passthrough(
                TunnelMode::Direct,
                OutboundId::new("home"),
            )),
            Arc::new(OutboundPool::new(dialer)),
            Arc::new(NoResolver),
            Metrics::new(),
        ));
        let hijacker = Arc::new(DnsHijacker::new(&DnsConfig::default()).expect("собирается"));
        let fake_ip = hijacker.fake_ip().cloned();
        let slow = fake_ip
            .as_ref()
            .expect("режим fake-IP")
            .address_for("slow.example")
            .expect("адрес выдан");

        let (to_pump, incoming) = mpsc::channel(8);
        let (outgoing, mut from_pump) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        tokio::spawn(pump(
            incoming,
            outgoing,
            pipeline,
            Some(hijacker),
            fake_ip,
            cancel.clone(),
        ));

        to_pump
            .send(Datagram {
                source: "198.18.0.1:50000".parse().expect("адрес"),
                destination: std::net::SocketAddr::new(slow.into(), 443),
                payload: Bytes::from_static(b"quic"),
            })
            .await
            .expect("насос жив");
        let query = message::build_query("fast.example", RecordType::A, 7).expect("запрос");
        to_pump
            .send(Datagram {
                source: "198.18.0.1:50001".parse().expect("адрес"),
                destination: "198.18.0.2:53".parse().expect("адрес"),
                payload: Bytes::from(query),
            })
            .await
            .expect("насос жив");

        let answer = tokio::time::timeout(Duration::from_secs(2), from_pump.recv())
            .await
            .expect("DNS ждал чужую датаграмму")
            .expect("ответ");
        assert_eq!(answer.destination.port(), DNS_PORT);
        cancel.cancel();
    }

    #[test]
    fn session_key_is_the_application_socket() {
        let first: SessionKey = "10.0.0.2:50000".parse().expect("адрес");
        let second: SessionKey = "10.0.0.2:50001".parse().expect("адрес");
        assert_ne!(first, second);
    }
}
