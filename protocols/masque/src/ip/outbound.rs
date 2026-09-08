//! Направление `CONNECT-IP`, надетое на [`PacketOutbound`].
//!
//! Один поток на весь профиль — в отличие от CONNECT-UDP, где на каждый
//! адрес назначения открывается свой канал ([`crate::datagram`]).
//! `CONNECT-IP` целиком реализован через капсулы над HTTP/1.1 `Upgrade`
//! (RFC 9484, §4.2—4.3), а не через расширенный CONNECT у HTTP/2/3 — почему,
//! см. [`crate::ip`].

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::id::OutboundId;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::packet::{PacketInterface, PacketOutbound};
use penguin_proto::stream::ProxyStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use super::capsule::{
    self, CAPSULE_TYPE_ADDRESS_ASSIGN, CAPSULE_TYPE_ADDRESS_REQUEST,
    CAPSULE_TYPE_ROUTE_ADVERTISEMENT, CONTEXT_ID_IP,
};
use super::{connect, negotiate};
use crate::capsule::{CAPSULE_TYPE_DATAGRAM, CapsuleReader, encode_datagram_capsule};
use crate::config::MasqueConfig;
use crate::error::{MasqueError, MasqueResult};
use crate::varint;

/// MTU тоннеля `CONNECT-IP`.
///
/// RFC 9484 не даёт способа сервера назвать MTU (в отличие от `X-CSTP-MTU` у
/// OpenConnect) — документ вообще не определяет такое согласование. Значение
/// не придумано: RFC 9484, §7.2 требует, чтобы звено, переносящее IPv6, было
/// не меньше 1280 байт. Это floor из самого документа, а не измеренный путь
/// — профиль, которому нужно больше, лечится отдельной работой.
pub(crate) const INTERFACE_MTU: u16 = 1280;

/// Сколько пакетов из тоннеля можно накопить, пока `recv()` их не забирает.
const QUEUE_LEN: usize = 512;

/// Наибольшая длина одного куска, читаемого из сети за раз.
const READ_CHUNK: usize = 4096;

/// Направление `CONNECT-IP`.
pub struct MasqueIpOutbound {
    id: OutboundId,
    interface: PacketInterface,
    send: Mutex<WriteHalf<Box<dyn ProxyStream>>>,
    incoming: Mutex<mpsc::Receiver<Result<Bytes, MasqueError>>>,
    reader: JoinHandle<()>,
}

impl std::fmt::Debug for MasqueIpOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueIpOutbound")
            .field("id", &self.id)
            .field("interface", &self.interface)
            .finish()
    }
}

impl MasqueIpOutbound {
    /// Заводит направление поверх уже открытого потока капсул: делит его на
    /// половины и запускает чтение.
    ///
    /// `reader` — то, что уже накоплено сверх согласования адреса (маршруты,
    /// а то и первый IP-пакет, пришедшие в одном куске с `ADDRESS_ASSIGN`) —
    /// его нельзя просто отбросить, начав читать сеть с нуля.
    fn new(
        id: OutboundId,
        io: Box<dyn ProxyStream>,
        reader: CapsuleReader,
        interface: PacketInterface,
    ) -> Self {
        let (read_half, write_half) = tokio::io::split(io);
        let (tx, rx) = mpsc::channel(QUEUE_LEN);
        let reader_task = tokio::spawn(read_loop(read_half, reader, tx));

        Self {
            id,
            interface,
            send: Mutex::new(write_half),
            incoming: Mutex::new(rx),
            reader: reader_task,
        }
    }

    /// Устанавливает соединение и держит его открытым на весь профиль.
    pub async fn connect(
        id: OutboundId,
        config: MasqueConfig,
        dialer: Arc<dyn Dialer>,
    ) -> MasqueResult<Self> {
        let (mut io, tail) = connect::open(dialer.as_ref(), &config).await?;

        let mut reader = CapsuleReader::new();
        reader.push(Bytes::from(tail));

        let interface = negotiate::assign_interface(&mut io, &mut reader).await?;

        Ok(Self::new(id, io, reader, interface))
    }
}

#[async_trait]
impl PacketOutbound for MasqueIpOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::ip::PROTOCOL_MASQUE_IP
    }

    fn interface(&self) -> PacketInterface {
        self.interface.clone()
    }

    async fn send(&self, packet: &[u8]) -> Result<(), ProtocolError> {
        if packet.len() > usize::from(self.interface.mtu) {
            return Err(ProtocolError::InvalidConfig(format!(
                "пакет в {} байт длиннее MTU тоннеля ({})",
                packet.len(),
                self.interface.mtu
            )));
        }
        let capsule = encode_datagram_capsule(CONTEXT_ID_IP, packet);
        let mut send = self.send.lock().await;
        send.write_all(&capsule).await?;
        send.flush().await?;
        Ok(())
    }

    async fn recv(&self) -> Result<Bytes, ProtocolError> {
        let mut incoming = self.incoming.lock().await;
        match incoming.recv().await {
            Some(Ok(packet)) => Ok(packet),
            Some(Err(err)) => Err(err.into()),
            // Отправитель — только фоновая задача чтения; пусто здесь
            // означает, что направление уже закрыто.
            None => Err(ProtocolError::Disconnected(
                "направление CONNECT-IP закрыто".to_owned(),
            )),
        }
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        // Без этого задача чтения переживает канал и держит его половину
        // потока открытой.
        self.reader.abort();
        Ok(())
    }
}

/// Читает капсулы из сети, раскладывая их по смыслу: IP-пакеты — в очередь
/// [`PacketOutbound::recv`], остальное — в журнал.
///
/// Останавливается сама, когда поток заканчивается, рвётся или приносит
/// капсулу не по формату — чинить её нечем, дальше в потоке байты сдвинуты
/// неизвестно на сколько.
async fn read_loop(
    mut io: ReadHalf<Box<dyn ProxyStream>>,
    mut reader: CapsuleReader,
    tx: mpsc::Sender<Result<Bytes, MasqueError>>,
) {
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        match dispatch_ready(&mut reader) {
            Ok(Some(Some(packet))) => {
                if tx.send(Ok(packet)).await.is_err() {
                    return;
                }
                continue;
            }
            Ok(Some(None)) => continue,
            Ok(None) => {}
            Err(err) => {
                let _ = tx.send(Err(err)).await;
                return;
            }
        }

        let read = match io.read(&mut chunk).await {
            Ok(0) => return, // сервер закрыл поток штатно
            Ok(n) => n,
            Err(err) => {
                let _ = tx.send(Err(MasqueError::Io(err))).await;
                return;
            }
        };
        reader.push(Bytes::copy_from_slice(&chunk[..read]));
    }
}

/// Разбирает и обрабатывает одну готовую капсулу.
///
/// `Ok(None)` — капсулы целиком ещё нет, нужно почитать сеть. `Ok(Some(None))`
/// — капсула была служебной и уже обработана. `Ok(Some(Some(_)))` — это был
/// IP-пакет.
fn dispatch_ready(reader: &mut CapsuleReader) -> MasqueResult<Option<Option<Bytes>>> {
    let Some((capsule_type, mut value)) = reader.next_capsule()? else {
        return Ok(None);
    };

    if capsule_type == CAPSULE_TYPE_DATAGRAM {
        let context_id = varint::decode_prefix(&mut value)
            .ok_or_else(|| MasqueError::malformed("капсула DATAGRAM без context ID"))?;
        if context_id != CONTEXT_ID_IP {
            // Контекст сжатия заголовков, которого этот клиент не
            // регистрировал (RFC 9484, §5) — разбирать нечем.
            return Ok(Some(None));
        }
        return Ok(Some(Some(value)));
    }

    if capsule_type == CAPSULE_TYPE_ROUTE_ADVERTISEMENT {
        let ranges = capsule::decode_route_advertisement(value)?;
        tracing::debug!(count = ranges.len(), "сервер обновил маршруты CONNECT-IP");
        return Ok(Some(None));
    }

    if capsule_type == CAPSULE_TYPE_ADDRESS_ASSIGN {
        // Переназначение адреса на лету не поддержано: интерфейс — снимок на
        // момент подключения, как и у WireGuard/OpenConnect.
        tracing::debug!(
            "сервер прислал повторный ADDRESS_ASSIGN — уже поднятый интерфейс не меняется"
        );
        return Ok(Some(None));
    }

    if capsule_type == CAPSULE_TYPE_ADDRESS_REQUEST {
        let requested = capsule::decode_address_request(value)?;
        tracing::warn!(
            count = requested.len(),
            "сервер запросил адрес у клиента — не поддержано, пропущено"
        );
        return Ok(Some(None));
    }

    // Неизвестный тип — пропускаем молча (RFC 9297, §3.2).
    Ok(Some(None))
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;
    use tokio::io::duplex;

    use super::*;

    fn interface() -> PacketInterface {
        PacketInterface {
            ipv4: ("203.0.113.9".parse().expect("адрес"), 32),
            ipv6: None,
            mtu: INTERFACE_MTU,
            dns: Vec::new(),
        }
    }

    fn outbound(io: Box<dyn ProxyStream>) -> MasqueIpOutbound {
        MasqueIpOutbound::new(
            OutboundId::new("проверка"),
            io,
            CapsuleReader::new(),
            interface(),
        )
    }

    #[tokio::test]
    async fn a_data_capsule_from_the_network_becomes_a_packet() {
        let (client, mut server) = duplex(4096);
        let outbound = outbound(Box::new(client));

        let capsule = encode_datagram_capsule(CONTEXT_ID_IP, b"IP-packet");
        server.write_all(&capsule).await.expect("ушло");

        let packet = outbound.recv().await.expect("пришло");
        assert_eq!(&packet[..], b"IP-packet");
    }

    #[tokio::test]
    async fn sending_wraps_the_packet_in_a_datagram_capsule() {
        let (client, mut server) = duplex(4096);
        let outbound = outbound(Box::new(client));

        outbound.send("наружу".as_bytes()).await.expect("ушло");

        let mut raw = vec![0u8; 64];
        let read = server.read(&mut raw).await.expect("капсула пришла");
        let mut reader = CapsuleReader::new();
        reader.push(Bytes::copy_from_slice(&raw[..read]));
        let (capsule_type, mut value) = reader
            .next_capsule()
            .expect("разбирается")
            .expect("капсула целиком пришла");
        assert_eq!(capsule_type, CAPSULE_TYPE_DATAGRAM);
        let context_id = varint::decode_prefix(&mut value).expect("context id есть");
        assert_eq!(context_id, CONTEXT_ID_IP);
        assert_eq!(&value[..], "наружу".as_bytes());
    }

    #[tokio::test]
    async fn a_packet_longer_than_the_mtu_is_refused_before_it_is_sent() {
        let (client, _server) = duplex(4096);
        let outbound = outbound(Box::new(client));
        let huge = vec![0u8; usize::from(INTERFACE_MTU) + 1];
        let err = outbound.send(&huge).await.expect_err("длиннее MTU");
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn an_unknown_capsule_type_is_skipped_not_reported() {
        let (client, mut server) = duplex(4096);
        let outbound = outbound(Box::new(client));

        let mut unknown = bytes::BytesMut::new();
        varint::encode(0x2a, &mut unknown);
        varint::encode(3, &mut unknown);
        unknown.put_slice(b"xyz");
        server.write_all(&unknown).await.expect("ушло");
        server
            .write_all(&encode_datagram_capsule(CONTEXT_ID_IP, b"real"))
            .await
            .expect("ушло");

        let packet = outbound.recv().await.expect("пришло");
        assert_eq!(&packet[..], b"real");
    }

    #[tokio::test]
    async fn dropping_the_server_side_ends_the_direction_with_a_retryable_error() {
        let (client, server) = duplex(4096);
        let outbound = outbound(Box::new(client));
        drop(server);

        let err = outbound.recv().await.expect_err("обрыв");
        assert!(err.is_retryable(), "{err}");
    }

    #[tokio::test]
    async fn close_leaves_no_task_running() {
        let (client, _server) = duplex(4096);
        let outbound = outbound(Box::new(client));
        outbound.close().await.expect("закрылось");

        // Абортнутая задача либо уже успела завершиться сама, либо это
        // видно по `JoinError::is_cancelled` — в обоих случаях `await` не
        // висит вечно и живой задачи после `close()` не остаётся.
        if let Err(join_err) = outbound.reader.await {
            assert!(join_err.is_cancelled());
        }
    }
}
