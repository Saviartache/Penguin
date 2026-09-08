//! `VisionStream<S>` — конверт набивки и переключение в прямой режим
//! (`flow = "xtls-rprx-vision"`) поверх [`RealityStream`].
//!
//! # Как устроены оба направления
//!
//! Пока направление внутри конверта (`is_padding`/`!done_padding`), каждый
//! вызов [`AsyncWrite::poll_write`]/каждый разобранный блок
//! [`AsyncRead::poll_read`] несёт один блок [`crate::vision::padding`]:
//! необязательный UUID (только у первого блока направления), команду,
//! длины и содержимое. Обе стороны досматривают содержимое блока
//! [`VisionState::filter`] в поисках признаков TLS 1.3 внутри тоннеля.
//!
//! Как только сторона, которая ПИШЕТ, видит на своём направлении цельные
//! записи `application_data` внутреннего TLS
//! ([`is_complete_tls_records`](crate::vision::state::is_complete_tls_records))
//! и в общем состоянии уже стоит `enable_xtls` (выставляется чтением
//! `ServerHello` — обычно на встречном направлении), она посылает `Direct`
//! вместо `End`: это последний блок в конверте, а начиная со следующего
//! вызова обе стороны обязаны читать и писать эти байты в обход
//! [`RecordKey::seal`](crate::reality::record::RecordKey::seal)/
//! [`RecordKey::open`](crate::reality::record::RecordKey::open) — то есть
//! без второго слоя шифрования, прямо через `RealityStream::io_mut`.
//!
//! До этого момента (и если оно вовсе не наступает — например, внутри
//! тоннеля не TLS, а что-то другое) канал работает ровно как без Vision:
//! только конверт набивки поверх обычного двойного шифрования.
//!
//! # Что сознательно не сделано
//!
//! - **Камуфляж заголовка VLESS** (`postRequest`, пустой блок набивки, если
//!   первых данных приложения не набралось за 500 мс) — Xray-core вставляет
//!   его, чтобы длина заголовка не была видна по первому пакету. Это
//!   ортогонально работе самого Vision (сервер прекрасно принимает первый
//!   настоящий блок в любой момент), и здесь не сделано.
//! - **`-udp443` и разбор порта 443 у UDP.** Эта реализация поддерживает
//!   ровно один `flow` — [`crate::frame::addons::FLOW_VISION`]; UDP у этого
//!   клиента и так идёт отдельным потоком на каждый адрес
//!   (`crate::datagram`), а не через мультиплексирование `v1.mux.cool`
//!   эталона, так что понятие "порт 443 в одном потоке с остальным UDP" к
//!   этой архитектуре не относится.
//! - **Досмотр не продолжается после `End`.** Эталон (`proxy.go`,
//!   `ReadMultiBuffer`) ещё несколько пакетов подряд разбирает конверт после
//!   окончания набивки — ровно до исчерпания общего бюджета — на случай,
//!   если `enable_xtls` появится чуть позже и *другое* направление успеет
//!   послать `Direct`. Здесь направление, пославшее или получившее `End`,
//!   перестаёт разбирать конверт сразу. В худшем случае это на пакет-другой
//!   позже отключает второй слой шифрования — не теряет его: пока условие
//!   не сработало, канал остаётся полностью зашифрованным, как и всегда.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::VlessError;
use crate::reality::RealityStream;
use crate::vision::padding::{self, Command};
use crate::vision::state::{self, VisionState};

/// Сколько байт вычитывать из [`RealityStream`] за раз, пока разбираем
/// конверт: не меньше самой большой возможной прикладной записи TLS 1.3
/// (`MAX_PLAINTEXT_RECORD`, `reality::application`) — иначе
/// `RealityStream::poll_read` мог бы оставить недочитанный хвост записи в
/// себе, а этот тип решил бы, что переключаться пора, пока сзади ещё лежат
/// неразобранные расшифрованные байты.
const SCRATCH: usize = 16 * 1024;

/// Сколько сырых байт принимать за один вызов после переключения — просто
/// разумный кусок, как и у остальных потоков этого крейта.
const RAW_CHUNK: usize = 8 * 1024;

/// Состояние записи: конверт набивки, потом (если сработало) — сырой канал.
struct WriteState {
    is_padding: bool,
    sent_uuid: bool,
    switched: bool,
    pending_switch: bool,
    /// Уже собранный блок конверта (или сырые байты после переключения),
    /// ещё не полностью ушедший в получатель.
    pending: Vec<u8>,
    offset: usize,
    /// Сколько байт исходного `buf` вызывающего представляет `pending` —
    /// возвращается из `poll_write` только после того, как `pending` ушёл
    /// целиком.
    accepted: usize,
    raw_sink: bool,
}

impl Default for WriteState {
    fn default() -> Self {
        Self {
            is_padding: true,
            sent_uuid: false,
            switched: false,
            pending_switch: false,
            pending: Vec::new(),
            offset: 0,
            accepted: 0,
            raw_sink: false,
        }
    }
}

/// Состояние чтения: конверт набивки, потом — сырой канал.
struct ReadState {
    done_padding: bool,
    switched: bool,
    seen_first_block: bool,
    /// Расшифрованные байты Reality, ещё не собранные в целый блок конверта.
    accumulate: BytesMut,
    /// Содержимое уже разобранных блоков (или сырые байты после
    /// переключения), ещё не отданное вызывающему.
    ready: BytesMut,
    /// Байты, снятые с провода вместе с последней зашифрованной записью, в
    /// момент переключения — см. [`RealityStream::take_undecrypted_read_bytes`].
    raw_after_switch: BytesMut,
}

impl Default for ReadState {
    fn default() -> Self {
        Self {
            done_padding: false,
            switched: false,
            seen_first_block: false,
            accumulate: BytesMut::new(),
            ready: BytesMut::new(),
            raw_after_switch: BytesMut::new(),
        }
    }
}

/// Поток VLESS-с-Vision поверх [`RealityStream`].
pub struct VisionStream<S> {
    reality: RealityStream<S>,
    uuid: [u8; 16],
    state: VisionState,
    write: WriteState,
    read: ReadState,
}

impl<S> std::fmt::Debug for VisionStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VisionStream")
            .field("write_switched", &self.write.switched)
            .field("read_switched", &self.read.switched)
            .finish_non_exhaustive()
    }
}

impl<S> VisionStream<S> {
    /// Оборачивает поток Reality, доведённый до прикладных ключей.
    /// `uuid` — UUID аккаунта: он же открывает первый блок конверта в обе
    /// стороны (`TrafficState.UserUUID`, `proxy.go`).
    pub(crate) fn new(reality: RealityStream<S>, uuid: [u8; 16]) -> Self {
        Self {
            reality,
            uuid,
            state: VisionState::default(),
            write: WriteState::default(),
            read: ReadState::default(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if !this.read.ready.is_empty() {
                let take = this.read.ready.len().min(buf.remaining());
                buf.put_slice(&this.read.ready[..take]);
                this.read.ready.advance(take);
                return Poll::Ready(Ok(()));
            }

            if this.read.switched {
                if !this.read.raw_after_switch.is_empty() {
                    let take = this.read.raw_after_switch.len().min(buf.remaining());
                    buf.put_slice(&this.read.raw_after_switch[..take]);
                    this.read.raw_after_switch.advance(take);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(this.reality.io_mut()).poll_read(cx, buf);
            }

            if this.read.done_padding {
                return Pin::new(&mut this.reality).poll_read(cx, buf);
            }

            match padding::parse_block(
                &this.read.accumulate,
                !this.read.seen_first_block,
                &this.uuid,
            ) {
                Ok(Some(block)) => {
                    this.read.seen_first_block = true;
                    let content = this.read.accumulate
                        [block.content_start..block.content_start + block.content_len]
                        .to_vec();
                    this.read.accumulate.advance(block.total_len);

                    if this.state.packets_to_filter > 0 {
                        this.state.filter(&content);
                    }
                    this.read.ready.extend_from_slice(&content);

                    match block.command {
                        Command::Continue => {}
                        Command::End => this.read.done_padding = true,
                        Command::Direct => {
                            this.read.done_padding = true;
                            this.read.switched = true;
                            let leftover = this.reality.take_undecrypted_read_bytes();
                            this.read.raw_after_switch.extend_from_slice(&leftover);
                        }
                    }
                    continue;
                }
                Ok(None) => {}
                Err(message) => return Poll::Ready(Err(as_malformed(message))),
            }

            let before = this.read.accumulate.len();
            this.read.accumulate.resize(before + SCRATCH, 0);
            let mut chunk = ReadBuf::new(&mut this.read.accumulate[before..]);
            let result = Pin::new(&mut this.reality).poll_read(cx, &mut chunk);
            let filled = chunk.filled().len();
            this.read.accumulate.truncate(before + filled);

            match result {
                Poll::Ready(Ok(())) if filled == 0 => {
                    if this.read.accumulate.is_empty() {
                        // Конец потока между блоками — обычное дело.
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(as_io(VlessError::Disconnected(
                        "сервер закрыл поток внутри блока Vision".to_owned(),
                    ))));
                }
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        loop {
            if !this.write.pending.is_empty() {
                let unsent = &this.write.pending[this.write.offset..];
                let sink_result = if this.write.raw_sink {
                    Pin::new(this.reality.io_mut()).poll_write(cx, unsent)
                } else {
                    Pin::new(&mut this.reality).poll_write(cx, unsent)
                };
                match sink_result {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "запись Vision оборвалась",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        this.write.offset += n;
                        if this.write.offset < this.write.pending.len() {
                            continue;
                        }
                        this.write.pending.clear();
                        this.write.offset = 0;
                        if this.write.pending_switch {
                            this.write.switched = true;
                            this.write.pending_switch = false;
                        }
                        return Poll::Ready(Ok(this.write.accepted));
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }

            if this.write.switched {
                let take = buf.len().min(RAW_CHUNK);
                this.write.pending = buf[..take].to_vec();
                this.write.accepted = take;
                this.write.raw_sink = true;
                continue;
            }

            let take = buf.len().min(padding::MAX_CONTENT);
            let content = &buf[..take];
            if this.state.packets_to_filter > 0 {
                this.state.filter(content);
            }

            if this.write.is_padding {
                let looks_like_inner_application_data = this.state.is_tls
                    && content.len() >= 6
                    && content.starts_with(&state::TLS_APPLICATION_DATA_START)
                    && state::is_complete_tls_records(content);

                let (command, will_switch) = if looks_like_inner_application_data {
                    if this.state.enable_xtls {
                        (Command::Direct, true)
                    } else {
                        (Command::End, false)
                    }
                } else if !this.state.is_tls12_or_above && this.state.packets_to_filter <= 1 {
                    (Command::End, false)
                } else {
                    (Command::Continue, false)
                };

                let long_padding = this.state.is_tls;
                let uuid = if this.write.sent_uuid {
                    None
                } else {
                    Some(&this.uuid)
                };
                let block = padding::pad(
                    uuid,
                    command,
                    content,
                    long_padding,
                    padding::DEFAULT_TESTSEED,
                    padding::random_below,
                );
                this.write.sent_uuid = true;
                this.write.pending = block;
                this.write.raw_sink = false;
                if command != Command::Continue {
                    this.write.is_padding = false;
                }
                if will_switch {
                    this.write.pending_switch = true;
                }
            } else {
                this.write.pending = content.to_vec();
                this.write.raw_sink = false;
            }
            this.write.accepted = take;
            continue;
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reality).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reality).poll_shutdown(cx)
    }
}

fn as_io(err: VlessError) -> io::Error {
    match err {
        VlessError::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

fn as_malformed(message: String) -> io::Error {
    as_io(VlessError::malformed(message))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::reality::cipher_suite::CipherSuite;
    use crate::reality::record::{CONTENT_TYPE_APPLICATION_DATA, RecordKey};
    use crate::vision::state::server_hello_tls13;

    const UUID: [u8; 16] = [9u8; 16];

    fn key_pair(seed: u8) -> (RecordKey, RecordKey) {
        let cipher = CipherSuite::Aes128GcmSha256;
        let key = vec![seed; cipher.key_len()];
        let iv = [seed; 12];
        (
            RecordKey::new(cipher, &key, iv).expect("ключ строится"),
            RecordKey::new(cipher, &key, iv).expect("ключ строится"),
        )
    }

    /// Снимает с `peer` ровно одну сброшенную Reality-запись (5-байтный
    /// заголовок плюс тело заявленной длины) — то, что реальный сервер читал
    /// бы с сокета, прежде чем расшифровать.
    async fn read_one_record(peer: &mut tokio::io::DuplexStream) -> Vec<u8> {
        let mut header = [0u8; 5];
        peer.read_exact(&mut header)
            .await
            .expect("заголовок пришёл");
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; len];
        peer.read_exact(&mut body).await.expect("тело пришло");
        let mut whole = header.to_vec();
        whole.extend_from_slice(&body);
        whole
    }

    #[tokio::test]
    async fn plain_content_round_trips_through_the_envelope() {
        let (client_write, server_read) = key_pair(1);
        let (_server_write, client_read) = key_pair(2);
        let (client_io, mut server_io) = duplex(8192);

        let reality = RealityStream::new(client_io, client_read, client_write);
        let mut client = VisionStream::new(reality, UUID);

        client.write_all(b"hello vision").await.expect("пишется");
        client.flush().await.expect("сбрасывается");

        // На проводе всё ещё обычная Reality-запись: снаружи — заголовок
        // `application_data` внешнего TLS, а конверт Vision — только внутри
        // расшифрованного содержимого.
        let record = read_one_record(&mut server_io).await;
        assert_eq!(record[0], CONTENT_TYPE_APPLICATION_DATA);

        let mut server_reader = server_read;
        let (_, plaintext) = server_reader
            .open(
                &record[..5].try_into().expect("пять байт"),
                &mut record[5..].to_vec(),
            )
            .expect("расшифровывается");

        let block = padding::parse_block(&plaintext, true, &UUID)
            .expect("разбирается")
            .expect("данных хватает");
        assert_eq!(
            &plaintext[block.content_start..block.content_start + block.content_len],
            b"hello vision"
        );
    }

    #[tokio::test]
    async fn writes_stay_sealed_while_the_switch_condition_has_not_fired() {
        // До срабатывания условия переключения канал обязан работать ровно
        // как без Vision — то есть каждая запись на проводе по-прежнему
        // Reality-запись, а не сырые байты.
        let (client_write, _server_read) = key_pair(3);
        let (_server_write, client_read) = key_pair(4);
        let (client_io, mut server_io) = duplex(8192);

        let reality = RealityStream::new(client_io, client_read, client_write);
        let mut client = VisionStream::new(reality, UUID);

        for chunk in [b"first ".as_slice(), b"second".as_slice()] {
            client.write_all(chunk).await.expect("пишется");
            client.flush().await.expect("сбрасывается");
            let record = read_one_record(&mut server_io).await;
            assert_eq!(
                record[0], CONTENT_TYPE_APPLICATION_DATA,
                "double-encryption ещё не снято"
            );
        }
    }

    #[tokio::test]
    async fn the_write_side_switches_to_a_raw_wire_only_after_seeing_inner_tls13() {
        let (client_write, server_read) = key_pair(5);
        let (mut server_write, client_read) = key_pair(6);
        let (client_io, mut server_io) = duplex(8192);

        let reality = RealityStream::new(client_io, client_read, client_write);
        let mut client = VisionStream::new(reality, UUID);

        // Шаг 1: клиент читает с "сервера" один блок конверта, чей груз —
        // ServerHello внутреннего TLS 1.3 с шифром, который эталон
        // принимает. Это выставляет `enable_xtls`, ровно как в жизни его
        // выставляет встречное направление.
        let hello_content = server_hello_tls13([0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        let block = padding::pad(
            Some(&UUID),
            Command::Continue,
            &hello_content,
            true,
            padding::DEFAULT_TESTSEED,
            |_| 0,
        );
        let sealed = server_write
            .seal(CONTENT_TYPE_APPLICATION_DATA, &block)
            .expect("шифруется");
        server_io.write_all(&sealed).await.expect("пишется");

        let mut got = vec![0u8; hello_content.len()];
        client.read_exact(&mut got).await.expect("читается");
        assert_eq!(got, hello_content);

        // Шаг 2: клиент пишет содержимое, похожее на цельные записи
        // application_data внутреннего TLS, — единственное условие,
        // недостающее для переключения (`enable_xtls` уже стоит).
        let mut inner_record = vec![0x17, 0x03, 0x03, 0x00, 0x05];
        inner_record.extend_from_slice(b"aaaaa");
        client.write_all(&inner_record).await.expect("пишется");
        client.flush().await.expect("сбрасывается");

        // Этот блок ушёл ещё через Reality: содержит команду Direct внутри
        // сегодняшнего шифрования, канал переключится только со следующей
        // записи.
        let record = read_one_record(&mut server_io).await;
        assert_eq!(record[0], CONTENT_TYPE_APPLICATION_DATA);
        let mut server_reader = server_read;
        let (_, plaintext) = server_reader
            .open(
                &record[..5].try_into().expect("пять байт"),
                &mut record[5..].to_vec(),
            )
            .expect("расшифровывается");
        // Это первая запись, которую клиент вообще пишет на этом
        // соединении, — конверт открывается с UUID, как и у любого первого
        // блока направления.
        let parsed = padding::parse_block(&plaintext, true, &UUID)
            .expect("разбирается")
            .expect("данных хватает");
        assert_eq!(parsed.command, Command::Direct);
        assert_eq!(
            &plaintext[parsed.content_start..parsed.content_start + parsed.content_len],
            inner_record.as_slice()
        );

        // Шаг 3: следующая запись — уже сырые байты, без внешнего
        // шифрования вовсе. Вот он, снятый второй слой.
        client
            .write_all(b"raw-after-switch")
            .await
            .expect("пишется");
        client.flush().await.expect("сбрасывается");
        let mut raw = vec![0u8; b"raw-after-switch".len()];
        server_io
            .read_exact(&mut raw)
            .await
            .expect("читается сырым");
        assert_eq!(&raw, b"raw-after-switch");
    }

    #[tokio::test]
    async fn the_read_side_switches_to_raw_delivery_including_bytes_from_the_same_packet() {
        let (client_write, _server_read) = key_pair(7);
        let (mut server_write, client_read) = key_pair(8);
        let (client_io, mut server_io) = duplex(8192);

        let reality = RealityStream::new(client_io, client_read, client_write);
        let mut client = VisionStream::new(reality, UUID);

        let first = padding::pad(
            Some(&UUID),
            Command::Continue,
            b"a",
            true,
            padding::DEFAULT_TESTSEED,
            |_| 0,
        );
        let last = padding::pad(
            None,
            Command::Direct,
            b"b",
            true,
            padding::DEFAULT_TESTSEED,
            |_| 0,
        );
        let mut plaintext = first;
        plaintext.extend_from_slice(&last);
        let sealed = server_write
            .seal(CONTENT_TYPE_APPLICATION_DATA, &plaintext)
            .expect("шифруется");

        // Сырые байты, пришедшие сразу вслед за последней зашифрованной
        // записью, в одном пакете, — ровно тот случай, ради которого
        // `RealityStream::take_undecrypted_read_bytes` вообще существует.
        let mut wire = sealed;
        wire.extend_from_slice(b"raw-tail");
        server_io.write_all(&wire).await.expect("пишется");

        let mut got = [0u8; 2 + 8];
        client.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"abraw-tail");
    }
}
