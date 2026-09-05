//! Единый поток `CONNECT _udp2` на весь UDP-трафик направления.
//!
//! Спецификация мультиплексирует **все** UDP-«соединения» в один поток
//! HTTP/2 (`PROTOCOL.md`, §6.1), а не заводит по потоку на каждый сокет
//! приложения, как это устроено с TCP. Значит, здесь ровно одна пара
//! читающей и пишущей задачи на направление, а не на вызов `bind_udp` —
//! то же устройство, что у `protocols/hysteria2` (`src/session/udp.rs`),
//! только канал там датаграммный (QUIC), а здесь потоковый (HTTP/2) и требует
//! собственной сборки кадров из кусков произвольной длины.
//!
//! ```text
//!                        ┌── сессия A (bind_udp #1) ──► приложение A
//! кадры _udp2 ──► разбор ┤
//!                        └── сессия B (bind_udp #2) ──► приложение B
//! ```
//!
//! # Как сессии узнают свои кадры
//!
//! Формат кадра не несёт опорного идентификатора сессии — только настоящие
//! сетевые адреса (`PROTOCOL.md`, §6.3–§6.5: сервер сам отслеживает
//! «соединения» по 4-элементному ключу и в ответе меняет источник с
//! назначением местами, см. `lib/src/forwarder.rs::UdpDatagramMeta::reversed`
//! эталона). У нас нет настоящего локального адреса — `ProxyDatagram::send_to`
//! его не принимает вовсе, — поэтому каждая сессия получает свой синтетический
//! адрес источника: `SESSION_SOURCE_IP` и уникальный порт. Он никогда не
//! используется для настоящей отправки — это просто метка, по которой кадр,
//! вернувшийся с тем же адресом в поле «назначение», находит свою сессию.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use dashmap::DashMap;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::connect;
use crate::error::{TrustTunnelError, TrustTunnelResult};
use crate::stream::H2Stream;
use crate::transport::H2SendRequest;
use crate::udp::frame;

/// Адрес источника у синтетических сессий этого крейта.
///
/// Не настоящий локальный адрес — здесь он и не нужен: сервер использует
/// это поле только как ключ (`PROTOCOL.md`, §6.5), а не как адрес, куда
/// действительно можно постучаться. Петлевой выбран затем, чтобы в журнале
/// такой адрес сразу читался как «это наша метка», а не как случайный адрес
/// сети клиента.
const SESSION_SOURCE_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Сколько кадров держать в очереди сессии, которая их не забирает.
///
/// Переполнение — потеря кадра, то есть ровно то, что и так случается с UDP.
/// Копить без предела значило бы, что забытый сокет приложения съедает
/// память клиента (то же рассуждение, что у `protocols/hysteria2`).
const SESSION_QUEUE: usize = 256;

/// Размер одного чтения из потока `_udp2`.
const READ_CHUNK: usize = 16 * 1024;

/// Единый поток `_udp2`: пишущая и читающая половины плюс таблица сессий.
pub struct UdpManager {
    dialer: Arc<dyn Dialer>,
    outbox: mpsc::Sender<Bytes>,
    sessions: Arc<DashMap<SocketAddr, mpsc::Sender<(Bytes, SocketAddress)>>>,
    next_port: AtomicU16,
    writer: JoinHandle<()>,
    reader: JoinHandle<()>,
}

impl std::fmt::Debug for UdpManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpManager")
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

impl UdpManager {
    /// Открывает поток `CONNECT _udp2` и заводит читающую и пишущую задачи.
    pub async fn connect(
        send_request: H2SendRequest,
        credentials: (&str, &str),
        dialer: Arc<dyn Dialer>,
    ) -> TrustTunnelResult<Arc<Self>> {
        let mut send_request = send_request
            .ready()
            .await
            .map_err(|e| TrustTunnelError::disconnected(e.to_string()))?;
        let request = connect::request_pseudo(connect::UDP_AUTHORITY, credentials)?;
        let (response, send_stream) = send_request
            .send_request(request, false)
            .map_err(|e| TrustTunnelError::transport(format!("запрос CONNECT _udp2: {e}")))?;

        let stream = connect::perform(connect::UDP_AUTHORITY, async {
            let response = response
                .await
                .map_err(|e| TrustTunnelError::disconnected(e.to_string()))?;
            let status = response.status().as_u16();
            let recv_stream = response.into_body();
            Ok((status, H2Stream::new(send_stream, recv_stream)))
        })
        .await?;

        let (read_half, write_half) = tokio::io::split(stream);
        let (outbox, inbox) = mpsc::channel(SESSION_QUEUE);
        let sessions: Arc<DashMap<SocketAddr, mpsc::Sender<(Bytes, SocketAddress)>>> =
            Arc::new(DashMap::new());

        let writer = tokio::spawn(write_loop(write_half, inbox));
        let reader = tokio::spawn(read_loop(read_half, Arc::clone(&sessions)));

        Ok(Arc::new(Self {
            dialer,
            outbox,
            sessions,
            // С единицы, а не с нуля: ноль слишком легко получить из
            // неинициализированного значения, и путать его с настоящей
            // сессией не хочется (тот же выбор, что у `hysteria2`).
            next_port: AtomicU16::new(1),
            writer,
            reader,
        }))
    }

    /// Открывает новую UDP-сессию поверх уже поднятого потока.
    pub fn open(self: &Arc<Self>) -> UdpSession {
        // Оборачивается: занятых портов не бывает больше 65535, а сессия,
        // владевшая портом раньше, к этому моменту почти наверняка уже
        // закрыта. Тот же компромисс, что у настоящего NAT с портовым пулом.
        let port = self.next_port.fetch_add(1, Ordering::Relaxed);
        let local = SocketAddr::new(SESSION_SOURCE_IP, port);

        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
        self.sessions.insert(local, tx);

        UdpSession {
            local,
            manager: Arc::clone(self),
            inbox: Mutex::new(rx),
        }
    }

    /// Останавливает читающую и пишущую задачи.
    pub fn shutdown(&self) {
        self.writer.abort();
        self.reader.abort();
    }
}

/// Пишет кадры в поток `_udp2` по мере поступления.
///
/// Отдельная задача, а не блокировка вокруг `WriteHalf`: несколько сессий
/// шлют кадры параллельно, а сам HTTP/2-поток — один, и писать в него нужно
/// строго по очереди.
async fn write_loop(mut write_half: WriteHalf<H2Stream>, mut inbox: mpsc::Receiver<Bytes>) {
    while let Some(frame) = inbox.recv().await {
        if let Err(err) = write_half.write_all(&frame).await {
            tracing::debug!(%err, "запись в поток _udp2 не удалась");
            return;
        }
    }
}

/// Читает поток `_udp2`, собирает кадры и раскладывает их по сессиям.
async fn read_loop(
    mut read_half: ReadHalf<H2Stream>,
    sessions: Arc<DashMap<SocketAddr, mpsc::Sender<(Bytes, SocketAddress)>>>,
) {
    let mut buffer = BytesMut::with_capacity(READ_CHUNK);

    loop {
        if buffer.capacity() - buffer.len() < READ_CHUNK {
            buffer.reserve(READ_CHUNK);
        }

        match read_half.read_buf(&mut buffer).await {
            Ok(0) => {
                tracing::debug!("поток _udp2 закрыт сервером");
                break;
            }
            Ok(_) => {}
            Err(err) => {
                tracing::debug!(%err, "чтение потока _udp2 оборвалось");
                break;
            }
        }

        loop {
            match frame::decode_server_frame(&buffer) {
                Ok(Some((decoded, used))) => {
                    buffer.advance(used);
                    dispatch(&sessions, decoded);
                }
                Ok(None) => break,
                Err(err) => {
                    // Кадр не разбирается — доверия к остальному потоку
                    // больше нет: сдвиг на один байт мог бы «починить»
                    // разбор молча, но с чужими данными в чужой сессии.
                    tracing::debug!(%err, "кадр _udp2 не разобрался, поток остановлен");
                    sessions.clear();
                    return;
                }
            }
        }
    }

    sessions.clear();
}

/// Передаёт разобранный кадр в его сессию по адресу назначения.
fn dispatch(
    sessions: &DashMap<SocketAddr, mpsc::Sender<(Bytes, SocketAddress)>>,
    frame: frame::ServerFrame,
) {
    let Some(sender) = sessions.get(&frame.destination) else {
        // Сессия уже закрыта: приложение закрыло сокет, а ответ был в пути.
        // Обычное дело для UDP.
        tracing::trace!(destination = %frame.destination, "кадр _udp2 для неизвестной сессии");
        return;
    };

    let source = SocketAddress::from(frame.source);
    if sender.try_send((frame.payload, source)).is_err() {
        tracing::trace!(destination = %frame.destination, "очередь UDP-сессии переполнена");
    }
}

/// Одна UDP-сессия: соответствует одному вызову `bind_udp`.
pub struct UdpSession {
    local: SocketAddr,
    manager: Arc<UdpManager>,
    inbox: Mutex<mpsc::Receiver<(Bytes, SocketAddress)>>,
}

impl std::fmt::Debug for UdpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSession")
            .field("local", &self.local)
            .finish()
    }
}

#[async_trait]
impl ProxyDatagram for UdpSession {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let destination = resolve_numeric(self.manager.dialer.as_ref(), target).await?;

        // Имя приложения этот крейт не знает (см. `crate::connect`) — идёт
        // пустая строка, легальная по формату (длина `0`).
        let frame = frame::encode_client_frame(self.local, destination, "", &payload)
            .map_err(ProtocolError::from)?;

        self.manager.outbox.send(frame).await.map_err(|_| {
            ProtocolError::from(TrustTunnelError::disconnected(
                "поток _udp2 закрыт".to_owned(),
            ))
        })
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut inbox = self.inbox.lock().await;
        inbox.recv().await.ok_or_else(|| {
            ProtocolError::from(TrustTunnelError::disconnected("сессия закрыта".to_owned()))
        })
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.manager.sessions.remove(&self.local);
        Ok(())
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        // Забытая запись в таблице означала бы, что чужие ответы копятся в
        // очереди, которую никто больше не читает.
        self.manager.sessions.remove(&self.local);
    }
}

/// Приводит адрес назначения к числовому: формат кадра не несёт имени
/// (`PROTOCOL.md`, §6.3 — только 16-байтовое поле IP), поэтому домен
/// разрешается здесь, а не на сервере, как это происходит с `CONNECT` у TCP.
async fn resolve_numeric(
    dialer: &dyn Dialer,
    target: &SocketAddress,
) -> Result<SocketAddr, ProtocolError> {
    if let Some(ip) = target.host.as_ip() {
        return Ok(SocketAddr::new(ip, target.port));
    }
    let addresses = penguin_proto::connect::resolve(dialer, &target.host, target.port).await?;
    addresses.into_iter().next().ok_or_else(|| {
        ProtocolError::Connect(format!("`{}` не разрешился ни в один адрес", target.host))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_do_not_start_at_zero() {
        // Ноль слишком легко получить из неинициализированного значения.
        let counter = AtomicU16::new(1);
        assert_eq!(counter.fetch_add(1, Ordering::Relaxed), 1);
    }

    #[test]
    fn the_source_tag_is_loopback_not_a_routable_address() {
        // Не адрес назначения ни для чего настоящего — только метка,
        // которую сервер обязан вернуть нам же в поле «назначение».
        assert!(SESSION_SOURCE_IP.is_loopback());
    }

    #[tokio::test]
    async fn a_numeric_target_needs_no_resolver() {
        struct NeverAsked;
        #[async_trait]
        impl Dialer for NeverAsked {
            async fn dial_tcp(
                &self,
                _addr: SocketAddr,
            ) -> Result<tokio::net::TcpStream, ProtocolError> {
                unreachable!("тест не открывает сокетов")
            }
            async fn bind_udp(
                &self,
                _local: SocketAddr,
            ) -> Result<tokio::net::UdpSocket, ProtocolError> {
                unreachable!("тест не открывает сокетов")
            }
            async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
                panic!("числовой адрес не должен идти к резолверу")
            }
        }

        let target = SocketAddress::ip("203.0.113.9".parse().unwrap(), 53);
        let resolved = resolve_numeric(&NeverAsked, &target)
            .await
            .expect("разрешился");
        assert_eq!(resolved, "203.0.113.9:53".parse().unwrap());
    }
}
