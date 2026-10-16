//! Прикладные записи TLS 1.3 (RFC 8446 §5) поверх канала с прикладными ключами.
//!
//! Шифрование двойное: VLESS сам не шифрует, а Reality доводит TLS до конца. Второй слой
//! снимает [`crate::vision`] через `RealityStream::io_mut`.
//!
//! `KeyUpdate` не поддержан ([`RealityError::KeyUpdateNotSupported`]); `NewSessionTicket`
//! отбрасывается: билеты не хранятся, а сервер шлёт их сам.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::reality::error::RealityError;
use crate::reality::record::{
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
    RecordKey,
};

/// Максимальный открытый текст записи (RFC 8446 §5.1).
const MAX_PLAINTEXT_RECORD: usize = 16_384;

/// `alert` (RFC 8446 §B.2).
const CONTENT_TYPE_ALERT: u8 = 0x15;
/// `NewSessionTicket` (RFC 8446 §B.3).
const HANDSHAKE_TYPE_NEW_SESSION_TICKET: u8 = 4;
/// `KeyUpdate` (RFC 8446 §B.3).
const HANDSHAKE_TYPE_KEY_UPDATE: u8 = 24;

/// Сколько байт брать из сети за раз: запись целиком.
const CHUNK: usize = 16 * 1024;

/// Поток VLESS поверх прикладных записей TLS 1.3.
pub struct RealityStream<S> {
    io: S,
    read_key: RecordKey,
    write_key: RecordKey,
    /// Байты с провода, не собранные в целую запись.
    read_raw: BytesMut,
    /// Расшифрованные байты, не отданные читателю.
    read_plain: BytesMut,
    /// Запись, не дописанная в `io`.
    write_pending: BytesMut,
    /// Сколько входа `poll_write` уже принято; возвращается, когда запись ушла целиком.
    write_accepted: usize,
}

impl<S> std::fmt::Debug for RealityStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityStream").finish_non_exhaustive()
    }
}

impl<S> RealityStream<S> {
    /// Оборачивает соединение с прикладными ключами: `read_key` для сервера, `write_key` для нас.
    pub(crate) fn new(io: S, read_key: RecordKey, write_key: RecordKey) -> Self {
        Self {
            io,
            read_key,
            write_key,
            read_raw: BytesMut::new(),
            read_plain: BytesMut::new(),
            write_pending: BytesMut::new(),
            write_accepted: 0,
        }
    }

    /// Поток под записями: Vision после `Direct` пишет и читает сюда без второго слоя.
    pub(crate) fn io_mut(&mut self) -> &mut S {
        &mut self.io
    }

    /// Байты, снятые с провода, но не собранные в запись: при переключении они уже не шифротекст.
    pub(crate) fn take_undecrypted_read_bytes(&mut self) -> BytesMut {
        std::mem::take(&mut self.read_raw)
    }
}

/// Итог одной записи, снятой с провода.
enum RecordOutcome {
    /// Данные VLESS.
    ApplicationData(BytesMut),
    /// `change_cipher_spec` или `NewSessionTicket`.
    Ignored,
}

/// Снимает с `raw` одну целую запись и расшифровывает её на месте; `Ok(None)` — запись не набралась.
fn take_record(
    raw: &mut BytesMut,
    key: &mut RecordKey,
) -> Result<Option<RecordOutcome>, RealityError> {
    if raw.len() < 5 {
        return Ok(None);
    }
    let total = 5 + usize::from(u16::from_be_bytes([raw[3], raw[4]]));
    if raw.len() < total {
        return Ok(None);
    }

    let mut record = raw.split_to(total);
    let header = [record[0], record[1], record[2], record[3], record[4]];
    match header[0] {
        CONTENT_TYPE_CHANGE_CIPHER_SPEC => return Ok(Some(RecordOutcome::Ignored)),
        CONTENT_TYPE_APPLICATION_DATA => {}
        other => {
            return Err(RealityError::Malformed(format!(
                "тип записи {other:#04x} после рукопожатия — не application_data (0x17)"
            )));
        }
    }

    let (inner_type, plaintext) = key.open_in_place(&header, &mut record[5..])?;
    let plain_len = plaintext.len();
    match inner_type {
        CONTENT_TYPE_APPLICATION_DATA => {
            record.advance(5);
            record.truncate(plain_len);
            Ok(Some(RecordOutcome::ApplicationData(record)))
        }
        CONTENT_TYPE_HANDSHAKE => match plaintext.first() {
            Some(&HANDSHAKE_TYPE_NEW_SESSION_TICKET) => Ok(Some(RecordOutcome::Ignored)),
            Some(&HANDSHAKE_TYPE_KEY_UPDATE) => Err(RealityError::KeyUpdateNotSupported),
            _ => Err(RealityError::Malformed(
                "сообщение рукопожатия после Finished — не NewSessionTicket и не KeyUpdate"
                    .to_owned(),
            )),
        },
        CONTENT_TYPE_ALERT => {
            let level = plaintext.first().copied().unwrap_or(0);
            let description = plaintext.get(1).copied().unwrap_or(0);
            Err(RealityError::Alert { level, description })
        }
        other => Err(RealityError::Malformed(format!(
            "запись несёт тип {other:#04x} — не данные VLESS"
        ))),
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RealityStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if !this.read_plain.is_empty() {
                let take = this.read_plain.len().min(buf.remaining());
                buf.put_slice(&this.read_plain[..take]);
                this.read_plain.advance(take);
                return Poll::Ready(Ok(()));
            }

            match take_record(&mut this.read_raw, &mut this.read_key) {
                Ok(Some(RecordOutcome::ApplicationData(data))) => {
                    this.read_plain = data;
                    continue;
                }
                Ok(Some(RecordOutcome::Ignored)) => continue,
                Ok(None) => {}
                Err(err) => return Poll::Ready(Err(as_io(err))),
            }

            let before = this.read_raw.len();
            this.read_raw.resize(before + CHUNK, 0);
            let mut chunk = ReadBuf::new(&mut this.read_raw[before..]);
            let result = Pin::new(&mut this.io).poll_read(cx, &mut chunk);
            let filled = chunk.filled().len();
            this.read_raw.truncate(before + filled);

            match result {
                Poll::Ready(Ok(())) if filled == 0 => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RealityStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.write_pending.is_empty() {
            let take = buf.len().min(MAX_PLAINTEXT_RECORD);
            if take == 0 {
                return Poll::Ready(Ok(0));
            }
            this.write_key
                .seal_into(
                    CONTENT_TYPE_APPLICATION_DATA,
                    &buf[..take],
                    &mut this.write_pending,
                )
                .map_err(as_io)?;
            this.write_accepted = take;
        }

        while !this.write_pending.is_empty() {
            match Pin::new(&mut this.io).poll_write(cx, &this.write_pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "запись в поток Reality оборвалась",
                    )));
                }
                Poll::Ready(Ok(n)) => this.write_pending.advance(n),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(this.write_accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

fn as_io(err: RealityError) -> io::Error {
    match err {
        RealityError::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::reality::cipher_suite::CipherSuite;

    /// Пара ключей клиента и сервера из общего секрета; вывод ключей проверен в `key_schedule.rs`.
    fn key_pair(cipher: CipherSuite, seed: u8) -> (RecordKey, RecordKey) {
        let key = vec![seed; cipher.key_len()];
        let iv = [seed; 12];
        (
            RecordKey::new(cipher, &key, iv).expect("ключ строится"),
            RecordKey::new(cipher, &key, iv).expect("ключ строится"),
        )
    }

    #[tokio::test]
    async fn a_round_trip_survives_the_double_wrapping() {
        let cipher = CipherSuite::Aes128GcmSha256;
        let (client_write, server_read) = key_pair(cipher, 1);
        let (server_write, client_read) = key_pair(cipher, 2);

        let (client_io, server_io) = duplex(8192);
        let mut client = RealityStream::new(client_io, client_read, client_write);
        let mut server = RealityStream::new(server_io, server_read, server_write);

        client.write_all(b"hello reality").await.expect("пишется");
        client.flush().await.expect("сбрасывается");

        let mut got = [0u8; 13];
        server.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"hello reality");
    }

    #[tokio::test]
    async fn a_new_session_ticket_is_skipped_not_delivered_as_data() {
        let cipher = CipherSuite::Aes128GcmSha256;
        let (mut server_write, client_read) = key_pair(cipher, 3);
        let client_write = ticket_key_placeholder(cipher);

        let (client_io, mut server_io) = duplex(8192);
        let mut client = RealityStream::new(client_io, client_read, client_write);

        let ticket = server_write
            .seal(CONTENT_TYPE_HANDSHAKE, &[0x04, 0, 0, 1, 0])
            .expect("шифруется");
        server_io.write_all(&ticket).await.expect("пишется");

        let data = server_write
            .seal(CONTENT_TYPE_APPLICATION_DATA, b"payload")
            .expect("шифруется");
        server_io.write_all(&data).await.expect("пишется");

        let mut got = [0u8; 7];
        client.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"payload");
    }

    /// Ключ для стороны, которая ничего не пишет.
    fn ticket_key_placeholder(cipher: CipherSuite) -> RecordKey {
        RecordKey::new(cipher, &vec![9; cipher.key_len()], [9; 12]).expect("ключ строится")
    }

    #[tokio::test]
    async fn a_key_update_request_is_refused_not_silently_accepted() {
        let cipher = CipherSuite::Aes128GcmSha256;
        let (mut sender_key, read_key) = key_pair(cipher, 5);
        let write_key = ticket_key_placeholder(cipher);

        let (client_io, mut server_io) = duplex(8192);
        let mut client = RealityStream::new(client_io, read_key, write_key);

        let update = sender_key
            .seal(CONTENT_TYPE_HANDSHAKE, &[0x18, 0, 0, 1, 0])
            .expect("шифруется");
        server_io.write_all(&update).await.expect("пишется");

        let mut buf = [0u8; 1];
        let err = client
            .read_exact(&mut buf)
            .await
            .expect_err("не поддержано");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
