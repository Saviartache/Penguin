//! Постоянное соединение с сервером: подлинность, потоки, датаграммы, `Heartbeat`.
//!
//! Рукопожатие QUIC и проверка подлинности платятся один раз, каждое
//! прикладное соединение — поток внутри него. Фоновых задач три: приём
//! датаграмм, приём односторонних потоков (режим `quic`) и `Heartbeat`
//! (иначе NAT забывает отображение).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_core::uuid::Uuid;
use penguin_transport::frag::{Fragment, Reassembler};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::{TuicConfig, UdpMode};
use crate::error::{TuicError, TuicResult};
use crate::frame::command::{self, Packet, TOKEN_LEN};
use crate::transport::QuicTransport;

/// Глубина очереди канала датаграмм.
const QUEUE: usize = 512;

/// Наибольший читаемый односторонний поток (одна датаграмма).
const MAX_UNI: usize = 64 * 1024;

/// Очередь на каждый канал датаграмм.
type Channels = Arc<parking_lot::Mutex<HashMap<u16, mpsc::Sender<(Bytes, SocketAddress)>>>>;

/// Установленный и представившийся сеанс.
pub struct Session {
    /// Владеет задачей ввода-вывода соединения.
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    mode: UdpMode,
    next_association: AtomicU16,
    channels: Channels,
    tasks: parking_lot::Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("mode", &self.mode)
            .field("channels", &self.channels.lock().len())
            .finish()
    }
}

fn disconnected(err: impl std::fmt::Display) -> TuicError {
    TuicError::Disconnected(err.to_string())
}

impl Session {
    /// Представляется серверу и запускает задачи сеанса.
    ///
    /// Отпечаток считается после рукопожатия: экспорт ключевого материала
    /// (метка — сырые байты UUID, контекст — пароль).
    pub async fn start(transport: QuicTransport, config: &TuicConfig) -> TuicResult<Arc<Self>> {
        let QuicTransport {
            endpoint,
            connection,
        } = transport;

        let token = export_token(&connection, &config.uuid, &config.password)?;
        authenticate(&connection, &config.uuid, &token).await?;

        let channels = Channels::default();
        let tasks = vec![
            tokio::spawn(read_datagrams(connection.clone(), Arc::clone(&channels))),
            tokio::spawn(read_uni_streams(connection.clone(), Arc::clone(&channels))),
            tokio::spawn(heartbeat(connection.clone(), config.heartbeat())),
        ];

        Ok(Arc::new(Self {
            _endpoint: endpoint,
            connection,
            mode: config.udp_mode,
            next_association: AtomicU16::new(1),
            channels,
            tasks: parking_lot::Mutex::new(tasks),
        }))
    }

    /// Открывает поток до адреса назначения; ответа нет, отказ виден как закрытие потока.
    pub async fn open(
        &self,
        target: &SocketAddress,
    ) -> TuicResult<(quinn::SendStream, quinn::RecvStream)> {
        let (mut send, recv) = self.connection.open_bi().await.map_err(disconnected)?;
        send.write_all(&command::connect(target)?)
            .await
            .map_err(disconnected)?;
        Ok((send, recv))
    }

    /// Заводит канал датаграмм: номер и очередь ответов.
    pub fn open_association(&self) -> (u16, mpsc::Receiver<(Bytes, SocketAddress)>) {
        let association = self.next_association.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(QUEUE);
        self.channels.lock().insert(association, sender);
        (association, receiver)
    }

    /// Закрывает канал и сообщает серверу, чтобы он освободил своё состояние.
    pub async fn close_association(&self, association: u16) {
        self.channels.lock().remove(&association);
        if let Ok(mut send) = self.connection.open_uni().await {
            let _ = send.write_all(&command::dissociate(association)).await;
            let _ = send.finish();
        }
    }

    /// Отправляет датаграмму, разрезав её, если она не помещается целиком.
    pub async fn send_packet(
        &self,
        association: u16,
        packet: u16,
        target: &SocketAddress,
        payload: &[u8],
    ) -> TuicResult<()> {
        match self.mode {
            UdpMode::Native => self.send_native(association, packet, target, payload),
            UdpMode::Quic => {
                self.send_over_stream(association, packet, target, payload)
                    .await
            }
        }
    }

    /// Датаграммами QUIC с разрезанием по путевому MTU.
    fn send_native(
        &self,
        association: u16,
        packet: u16,
        target: &SocketAddress,
        payload: &[u8],
    ) -> TuicResult<()> {
        let limit = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| TuicError::malformed("сервер не принимает датаграммы QUIC"))?;

        let parts = split(payload, limit, target)?;
        let total = u8::try_from(parts.len())
            .map_err(|_| TuicError::malformed("датаграмма не режется меньше чем на 256 частей"))?;

        for (index, part) in parts.into_iter().enumerate() {
            // Адрес только в первой части.
            let header = Packet {
                association,
                packet,
                fragments: total,
                fragment: index as u16,
                size: u16::try_from(part.len())
                    .map_err(|_| TuicError::malformed("часть длиннее 65535 байт"))?,
                address: (index == 0).then(|| target.clone()),
            };

            let mut wire = Vec::with_capacity(header.encoded_len() + part.len());
            header.encode_into(&mut wire)?;
            wire.extend_from_slice(part);
            self.connection
                .send_datagram(Bytes::from(wire))
                .map_err(disconnected)?;
        }
        Ok(())
    }

    /// Односторонним потоком целиком, без разрезания.
    async fn send_over_stream(
        &self,
        association: u16,
        packet: u16,
        target: &SocketAddress,
        payload: &[u8],
    ) -> TuicResult<()> {
        let header = Packet {
            association,
            packet,
            fragments: 1,
            fragment: 0,
            size: u16::try_from(payload.len())
                .map_err(|_| TuicError::malformed("датаграмма длиннее 65535 байт"))?,
            address: Some(target.clone()),
        };

        let mut wire = Vec::with_capacity(header.encoded_len() + payload.len());
        header.encode_into(&mut wire)?;
        wire.extend_from_slice(payload);

        let mut send = self.connection.open_uni().await.map_err(disconnected)?;
        send.write_all(&wire).await.map_err(disconnected)?;
        send.finish().map_err(disconnected)?;
        Ok(())
    }

    /// Соединение ещё живо.
    pub fn is_alive(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    /// Закрывает соединение и останавливает задачи.
    pub fn close(&self) {
        for task in self.tasks.lock().drain(..) {
            task.abort();
        }
        self.channels.lock().clear();
        self.connection.close(0u32.into(), b"");
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

/// Режет данные на части, помещающиеся в датаграмму QUIC.
fn split<'a>(payload: &'a [u8], limit: usize, target: &SocketAddress) -> TuicResult<Vec<&'a [u8]>> {
    // Худший случай для всех частей: заголовок с адресом.
    let header = 2 + 8 + crate::frame::address::encoded_len(Some(target));
    let room = limit
        .checked_sub(header)
        .filter(|room| *room > 0)
        .ok_or_else(|| {
            TuicError::malformed(format!(
                "датаграмма QUIC в {limit} байт короче заголовка в {header}"
            ))
        })?;

    if payload.is_empty() {
        return Ok(vec![payload]);
    }
    Ok(payload.chunks(room).collect())
}

/// Отпечаток проверки подлинности из ключевого материала соединения.
fn export_token(
    connection: &quinn::Connection,
    uuid: &Uuid,
    password: &str,
) -> TuicResult<[u8; TOKEN_LEN]> {
    let mut token = [0u8; TOKEN_LEN];
    connection
        // Метка — сырые байты UUID, как `string(uuid[:])` в эталоне.
        .export_keying_material(&mut token, uuid.as_bytes(), password.as_bytes())
        .map_err(|_| TuicError::malformed("соединение не отдаёт ключевой материал"))?;
    Ok(token)
}

/// Представляется серверу односторонним потоком.
async fn authenticate(
    connection: &quinn::Connection,
    uuid: &Uuid,
    token: &[u8; TOKEN_LEN],
) -> TuicResult<()> {
    let mut send = connection.open_uni().await.map_err(disconnected)?;
    send.write_all(&command::authenticate(uuid, token))
        .await
        .map_err(disconnected)?;
    send.finish().map_err(disconnected)?;
    Ok(())
}

/// Читает датаграммы QUIC и раскладывает их по каналам.
async fn read_datagrams(connection: quinn::Connection, channels: Channels) {
    let mut reassembler = Reassembler::new();

    loop {
        match connection.read_datagram().await {
            Ok(datagram) => deliver(&datagram, &mut reassembler, &channels),
            Err(err) => {
                tracing::debug!(%err, "приём датаграмм закончился");
                return;
            }
        }
    }
}

/// Читает односторонние потоки: ими сервер шлёт датаграммы в режиме `quic`.
async fn read_uni_streams(connection: quinn::Connection, channels: Channels) {
    let mut reassembler = Reassembler::new();

    loop {
        let mut recv = match connection.accept_uni().await {
            Ok(recv) => recv,
            Err(err) => {
                tracing::debug!(%err, "приём односторонних потоков закончился");
                return;
            }
        };

        match recv.read_to_end(MAX_UNI).await {
            Ok(bytes) => deliver(&Bytes::from(bytes), &mut reassembler, &channels),
            Err(err) => tracing::debug!(%err, "односторонний поток не дочитался"),
        }
    }
}

/// Разбирает пришедшее и кладёт готовую датаграмму в её канал.
fn deliver(bytes: &Bytes, reassembler: &mut Reassembler<SocketAddress>, channels: &Channels) {
    let Some((kind, used)) = command::read_head(bytes).ok().flatten() else {
        return;
    };
    if kind != command::CMD_PACKET {
        return;
    }

    let Ok(Some((header, header_len))) = Packet::decode(&bytes[used..]) else {
        return;
    };
    let start = used + header_len;
    let end = start + usize::from(header.size);
    if end > bytes.len() {
        return;
    }

    let association = header.association;
    let fragment = Fragment {
        session: u64::from(association),
        packet: header.packet,
        count: header.fragments,
        index: u8::try_from(header.fragment).unwrap_or(u8::MAX),
        // У остальных частей адрес берёт собиратель из первой.
        address: header
            .address
            .unwrap_or_else(|| SocketAddress::domain("", 0)),
        payload: bytes.slice(start..end),
    };
    if let Some((joined, address)) = reassembler.accept(fragment) {
        send_to_channel(channels, association, joined, address);
    }
}

/// Кладёт датаграмму в очередь канала; при переполнении теряет, как UDP.
fn send_to_channel(channels: &Channels, association: u16, payload: Bytes, address: SocketAddress) {
    let Some(sender) = channels.lock().get(&association).cloned() else {
        return;
    };
    if sender.try_send((payload, address)).is_err() {
        tracing::trace!(
            association,
            "очередь канала полна или закрыта, датаграмма отброшена"
        );
    }
}

/// Напоминает серверу о себе.
async fn heartbeat(connection: quinn::Connection, every: std::time::Duration) {
    let mut ticker = tokio::time::interval(every);
    ticker.tick().await;

    loop {
        ticker.tick().await;
        if connection
            .send_datagram(Bytes::from(command::heartbeat()))
            .is_err()
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SocketAddress {
        SocketAddress::domain("dns.example.com", 53)
    }

    #[test]
    fn a_small_datagram_stays_whole() {
        let parts = split(b"query", 1200, &target()).expect("режется");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], b"query");
    }

    #[test]
    fn a_big_datagram_is_cut_to_fit() {
        let payload = vec![7u8; 4000];
        let parts = split(&payload, 1200, &target()).expect("режется");

        assert!(parts.len() > 1, "не разрезана");
        let header = 2 + 8 + crate::frame::address::encoded_len(Some(&target()));
        for part in &parts {
            assert!(
                part.len() + header <= 1200,
                "часть с заголовком не помещается в датаграмму"
            );
        }
        let joined: Vec<u8> = parts.concat();
        assert_eq!(joined, payload, "склеенное не совпало с исходным");
    }

    #[test]
    fn an_empty_datagram_is_still_one_part() {
        let parts = split(b"", 1200, &target()).expect("режется");
        assert_eq!(parts.len(), 1);
        assert!(parts[0].is_empty());
    }

    #[test]
    fn a_datagram_smaller_than_the_header_is_refused() {
        assert!(split(b"query", 8, &target()).is_err());
    }
}
