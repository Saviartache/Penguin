//! Соединение целиком: подлинность, потоки, датаграммы, напоминания о себе.
//!
//! # Одно соединение на профиль
//!
//! У TUIC, в отличие от SOCKS5 и Trojan, соединение постоянное: рукопожатие
//! QUIC и проверка подлинности платятся **один раз**, а дальше каждое
//! прикладное соединение — это поток внутри уже установленного. Отсюда
//! [`Capabilities::multiplex`](penguin_proto::capabilities::Capabilities)
//! у него `true`: маршрутизатор вправе считать открытие потока дешёвым.
//!
//! # Что здесь крутится само
//!
//! Две задачи на всё соединение:
//!
//! - **приём** — читает датаграммы и односторонние потоки, собирает из частей
//!   целые датаграммы и раскладывает их по каналам;
//! - **напоминание о себе** — шлёт `Heartbeat`. Без него шлюз с
//!   преобразованием адресов забывает отображение через минуту молчания, и
//!   соединение умирает, не сказав ни слова.
//!
//! Обе останавливаются вместе с сеансом: задача, читающая закрытое
//! соединение, кончается сама, а напоминание снимается явно.

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

/// Сколько датаграмм держать в очереди канала, пока их не забрали.
const QUEUE: usize = 512;

/// Наибольший односторонний поток, который мы согласны прочитать.
///
/// Односторонним потоком приезжает одна датаграмма. Верить объявленному без
/// предела значит отдать памяти столько, сколько скажет сервер.
const MAX_UNI: usize = 64 * 1024;

/// Куда складываются пришедшие датаграммы: очередь на каждый канал.
type Channels = Arc<parking_lot::Mutex<HashMap<u16, mpsc::Sender<(Bytes, SocketAddress)>>>>;

/// Установленный и представившийся сеанс.
pub struct Session {
    /// Эндпойнт держится рядом: он владеет задачей ввода-вывода.
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    mode: UdpMode,
    /// Номер следующего канала датаграмм.
    next_association: AtomicU16,
    /// Куда складывать датаграммы каждого канала.
    channels: Channels,
    /// Задачи, живущие вместе с сеансом.
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

impl Session {
    /// Представляется серверу и запускает задачи сеанса.
    ///
    /// Отпечаток берётся **после** рукопожатия и из него самого: тридцать два
    /// байта экспорта ключевого материала, где метка — шестнадцать сырых байт
    /// UUID, а исходные данные — пароль. Посчитать его заранее нельзя, и в
    /// этом весь смысл: подслушанный в одном соединении, в другом он не
    /// подойдёт.
    pub async fn start(transport: QuicTransport, config: &TuicConfig) -> TuicResult<Arc<Self>> {
        let QuicTransport {
            endpoint,
            connection,
        } = transport;

        let token = export_token(&connection, &config.uuid, &config.password)?;
        authenticate(&connection, &config.uuid, &token).await?;

        let session = Arc::new(Self {
            _endpoint: endpoint,
            connection: connection.clone(),
            mode: config.udp_mode,
            next_association: AtomicU16::new(1),
            channels: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            tasks: parking_lot::Mutex::new(Vec::new()),
        });

        let channels = Arc::clone(&session.channels);
        let mut tasks = vec![
            tokio::spawn(read_datagrams(connection.clone(), Arc::clone(&channels))),
            tokio::spawn(read_uni_streams(connection.clone(), channels)),
        ];
        tasks.push(tokio::spawn(heartbeat(connection, config.heartbeat())));
        session.tasks.lock().extend(tasks);

        Ok(session)
    }

    /// Открывает поток до адреса назначения.
    ///
    /// Ответа сервер не шлёт: данные идут сразу за командой. Значит, отказ
    /// виден только тем, что поток закрылся, — и различить его от
    /// недостижимого адреса нечем.
    pub async fn open(
        &self,
        target: &SocketAddress,
    ) -> TuicResult<(quinn::SendStream, quinn::RecvStream)> {
        let (mut send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| TuicError::Disconnected(e.to_string()))?;

        let command = command::connect(target)?;
        send.write_all(&command)
            .await
            .map_err(|e| TuicError::Disconnected(e.to_string()))?;
        Ok((send, recv))
    }

    /// Заводит канал датаграмм и возвращает его номер и очередь ответов.
    pub fn open_association(&self) -> (u16, mpsc::Receiver<(Bytes, SocketAddress)>) {
        let association = self.next_association.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(QUEUE);
        self.channels.lock().insert(association, sender);
        (association, receiver)
    }

    /// Закрывает канал датаграмм и сообщает об этом серверу.
    pub async fn close_association(&self, association: u16) {
        self.channels.lock().remove(&association);

        // Сервер держит за каналом своё состояние — сокет и таблицу адресов.
        // Не сказать ему значит оставить это висеть до его собственного срока.
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
            UdpMode::Native => self.send_native(association, packet, target, payload).await,
            UdpMode::Quic => {
                self.send_over_stream(association, packet, target, payload)
                    .await
            }
        }
    }

    /// Датаграммами QUIC, с разрезанием по путевому MTU.
    async fn send_native(
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
            // Адрес назван один раз, в первой части: повторять его незачем, и
            // протокол этого не ждёт.
            let address = if index == 0 {
                Some(target.clone())
            } else {
                None
            };
            let header = Packet {
                association,
                packet,
                fragments: total,
                fragment: index as u16,
                size: u16::try_from(part.len())
                    .map_err(|_| TuicError::malformed("часть длиннее 65535 байт"))?,
                address,
            };

            let mut wire = header.encode()?;
            wire.extend_from_slice(part);
            self.connection
                .send_datagram(Bytes::from(wire))
                .map_err(|e| TuicError::Disconnected(e.to_string()))?;
        }
        Ok(())
    }

    /// Односторонним потоком, целиком и без разрезания.
    ///
    /// У потока предела длины нет, поэтому части здесь не нужны: датаграмма
    /// едет одной командой.
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

        let mut wire = header.encode()?;
        wire.extend_from_slice(payload);

        let mut send = self
            .connection
            .open_uni()
            .await
            .map_err(|e| TuicError::Disconnected(e.to_string()))?;
        send.write_all(&wire)
            .await
            .map_err(|e| TuicError::Disconnected(e.to_string()))?;
        send.finish()
            .map_err(|e| TuicError::Disconnected(e.to_string()))?;
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
///
/// Свободная функция с тестом: ошибка здесь даёт части, которые сервер не
/// соберёт, а видно это будет как «UDP не работает, а TCP работает».
fn split<'a>(payload: &'a [u8], limit: usize, target: &SocketAddress) -> TuicResult<Vec<&'a [u8]>> {
    // Заголовок первой части длиннее остальных на адрес; чтобы не считать
    // два предела, берём худший случай для всех.
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
        // Метка — шестнадцать сырых байт UUID, а не его запись с дефисами.
        // В эталоне это `string(uuid[:])`, то есть побайтовое преобразование.
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
    let mut send = connection
        .open_uni()
        .await
        .map_err(|e| TuicError::Disconnected(e.to_string()))?;

    send.write_all(&command::authenticate(uuid, token))
        .await
        .map_err(|e| TuicError::Disconnected(e.to_string()))?;
    send.finish()
        .map_err(|e| TuicError::Disconnected(e.to_string()))?;
    Ok(())
}

/// Читает датаграммы QUIC и раскладывает их по каналам.
async fn read_datagrams(connection: quinn::Connection, channels: Channels) {
    // Собиратель живёт в задаче и никем не разделяется: только сюда приходят
    // части, и замок вокруг него был бы замком самого с собой.
    let mut reassembler = Reassembler::new();

    loop {
        let datagram = match connection.read_datagram().await {
            Ok(datagram) => datagram,
            Err(err) => {
                tracing::debug!(%err, "приём датаграмм закончился");
                return;
            }
        };
        deliver(&datagram, &mut reassembler, &channels).await;
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
            Ok(bytes) => deliver(&bytes, &mut reassembler, &channels).await,
            Err(err) => tracing::debug!(%err, "односторонний поток не дочитался"),
        }
    }
}

/// Разбирает пришедшее и кладёт готовую датаграмму в её канал.
async fn deliver(bytes: &[u8], reassembler: &mut Reassembler<SocketAddress>, channels: &Channels) {
    let Some((kind, used)) = command::read_head(bytes).ok().flatten() else {
        // Повреждённое сообщение. Жаловаться некому — на той стороне UDP, и
        // единственное разумное действие тут выбросить.
        return;
    };
    if kind != command::CMD_PACKET {
        return;
    }

    let Ok(Some((header, header_len))) = Packet::decode(&bytes[used..]) else {
        return;
    };
    let start = used + header_len;
    let Some(payload) = bytes.get(start..start + usize::from(header.size)) else {
        return;
    };

    // Адрес есть только у первой части; у остальных его берёт собиратель из
    // той, что пришла первой.
    let Some(address) = header.address.clone() else {
        // Часть без адреса и без начатой сборки собрать не из чего.
        let fragment = Fragment {
            session: u64::from(header.association),
            packet: header.packet,
            count: header.fragments,
            index: u8::try_from(header.fragment).unwrap_or(u8::MAX),
            address: SocketAddress::domain("", 0),
            payload: Bytes::copy_from_slice(payload),
        };
        if let Some((joined, address)) = reassembler.accept(fragment) {
            send_to_channel(channels, header.association, joined, address).await;
        }
        return;
    };

    let fragment = Fragment {
        session: u64::from(header.association),
        packet: header.packet,
        count: header.fragments,
        index: u8::try_from(header.fragment).unwrap_or(u8::MAX),
        address,
        payload: Bytes::copy_from_slice(payload),
    };
    if let Some((joined, address)) = reassembler.accept(fragment) {
        send_to_channel(channels, header.association, joined, address).await;
    }
}

/// Кладёт готовую датаграмму в очередь её канала.
async fn send_to_channel(
    channels: &Channels,
    association: u16,
    payload: Bytes,
    address: SocketAddress,
) {
    let sender = channels.lock().get(&association).cloned();
    let Some(sender) = sender else {
        // Канал успели закрыть: датаграмма опоздала. Для UDP это то же самое,
        // что потерянный пакет.
        return;
    };
    if sender.send((payload, address)).await.is_err() {
        tracing::debug!(association, "канал датаграмм закрыт");
    }
}

/// Напоминает серверу о себе.
async fn heartbeat(connection: quinn::Connection, every: std::time::Duration) {
    let mut ticker = tokio::time::interval(every);
    // Первый тик приходит сразу; напоминать о себе в тот же миг, когда
    // соединение установлено, незачем.
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
        // Подавляющее большинство трафика — целые датаграммы; резать их значит
        // платить заголовком дважды.
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
        // Пустая датаграмма законна: её шлют, чтобы открыть путь через NAT.
        let parts = split(b"", 1200, &target()).expect("режется");
        assert_eq!(parts.len(), 1);
        assert!(parts[0].is_empty());
    }

    #[test]
    fn a_datagram_smaller_than_the_header_is_refused() {
        // Иначе получились бы части по нулю байт, и датаграмма не уехала бы
        // никогда — молча.
        assert!(split(b"query", 8, &target()).is_err());
    }
}
