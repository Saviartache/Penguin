//! `VisionStream<S>`: конверт набивки и переключение в прямой режим
//! (`flow = "xtls-rprx-vision"`) поверх [`RealityStream`].
//!
//! Пока направление в конверте, каждая запись и каждый прочитанный блок несут один блок
//! [`crate::vision::padding`]; содержимое досматривает [`VisionState::filter`]. Когда пишущая
//! сторона видит цельные записи `application_data` внутреннего TLS и стоит `enable_xtls`, она
//! шлёт `Direct`, и дальше обе стороны идут через `RealityStream::io_mut` без второго слоя.
//!
//! Не сделано: камуфляж заголовка (`postRequest`), `-udp443`, разбор конверта после `End`
//! (худший случай: второй слой снимается на пакет-другой позже).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::VlessError;
use crate::reality::RealityStream;
use crate::vision::padding::{self, Command};
use crate::vision::state::{self, VisionState};

/// Чтение за раз при разборе конверта: не меньше записи TLS 1.3, иначе хвост записи останется в `RealityStream`.
const SCRATCH: usize = 16 * 1024;

/// Сколько сырых байт писать за вызов после переключения.
const RAW_CHUNK: usize = 8 * 1024;

/// Состояние записи.
#[derive(Default)]
struct WriteState {
    /// Конверт закончен (`End` или `Direct`).
    padding_done: bool,
    sent_uuid: bool,
    switched: bool,
    pending_switch: bool,
    /// Блок конверта, не ушедший целиком.
    pending: Vec<u8>,
    offset: usize,
    /// Сколько байт `buf` вызывающего представляет `pending`.
    accepted: usize,
}

/// Состояние чтения.
#[derive(Default)]
struct ReadState {
    done_padding: bool,
    switched: bool,
    seen_first_block: bool,
    /// Расшифрованные байты, не собранные в блок конверта.
    accumulate: BytesMut,
    /// Содержимое разобранных блоков, не отданное вызывающему.
    ready: BytesMut,
    /// Сырые байты, пришедшие с последней зашифрованной записью.
    raw_after_switch: BytesMut,
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
    /// Оборачивает поток Reality; `uuid` открывает первый блок конверта в обе стороны.
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
                    let content = &this.read.accumulate
                        [block.content_start..block.content_start + block.content_len];
                    if this.state.packets_to_filter > 0 {
                        this.state.filter(content);
                    }
                    this.read.ready.extend_from_slice(content);
                    this.read.accumulate.advance(block.total_len);

                    match block.command {
                        Command::Continue => {}
                        Command::End => this.read.done_padding = true,
                        Command::Direct => {
                            this.read.done_padding = true;
                            this.read.switched = true;
                            this.read.raw_after_switch = this.reality.take_undecrypted_read_bytes();
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
                match Pin::new(&mut this.reality).poll_write(cx, unsent) {
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
                return Pin::new(this.reality.io_mut()).poll_write(cx, &buf[..take]);
            }
            if this.write.padding_done && this.state.packets_to_filter == 0 {
                return Pin::new(&mut this.reality).poll_write(cx, buf);
            }

            let take = buf.len().min(padding::MAX_CONTENT);
            let content = &buf[..take];
            if this.state.packets_to_filter > 0 {
                this.state.filter(content);
            }
            if this.write.padding_done {
                this.write.pending.extend_from_slice(content);
                this.write.accepted = take;
                continue;
            }

            let looks_like_inner_application_data = this.state.is_tls
                && content.len() >= 6
                && content.starts_with(&state::TLS_APPLICATION_DATA_START)
                && state::is_complete_tls_records(content);

            let command = if looks_like_inner_application_data {
                if this.state.enable_xtls {
                    Command::Direct
                } else {
                    Command::End
                }
            } else if !this.state.is_tls12_or_above && this.state.packets_to_filter <= 1 {
                Command::End
            } else {
                Command::Continue
            };

            let uuid = (!this.write.sent_uuid).then_some(&this.uuid);
            this.write.pending = padding::pad(
                uuid,
                command,
                content,
                this.state.is_tls,
                padding::DEFAULT_TESTSEED,
                padding::random_below,
            );
            this.write.sent_uuid = true;
            this.write.padding_done = command != Command::Continue;
            this.write.pending_switch = command == Command::Direct;
            this.write.accepted = take;
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

    /// Одна Reality-запись целиком (заголовок и тело).
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

        // Шаг 1: ServerHello внутреннего TLS 1.3 выставляет `enable_xtls`.
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

        // Шаг 2: цельные записи application_data внутреннего TLS.
        let mut inner_record = vec![0x17, 0x03, 0x03, 0x00, 0x05];
        inner_record.extend_from_slice(b"aaaaa");
        client.write_all(&inner_record).await.expect("пишется");
        client.flush().await.expect("сбрасывается");

        // Блок с `Direct` ещё идёт через Reality.
        let record = read_one_record(&mut server_io).await;
        assert_eq!(record[0], CONTENT_TYPE_APPLICATION_DATA);
        let mut server_reader = server_read;
        let (_, plaintext) = server_reader
            .open(
                &record[..5].try_into().expect("пять байт"),
                &mut record[5..].to_vec(),
            )
            .expect("расшифровывается");
        let parsed = padding::parse_block(&plaintext, true, &UUID)
            .expect("разбирается")
            .expect("данных хватает");
        assert_eq!(parsed.command, Command::Direct);
        assert_eq!(
            &plaintext[parsed.content_start..parsed.content_start + parsed.content_len],
            inner_record.as_slice()
        );

        // Шаг 3: сырые байты без внешнего шифрования.
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

        // Сырые байты в одном пакете с последней зашифрованной записью.
        let mut wire = sealed;
        wire.extend_from_slice(b"raw-tail");
        server_io.write_all(&wire).await.expect("пишется");

        let mut got = [0u8; 2 + 8];
        client.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"abraw-tail");
    }
}
