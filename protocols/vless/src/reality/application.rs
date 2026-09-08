//! Слой прикладных записей TLS 1.3 (RFC 8446 §5) поверх канала, доведённого
//! [`crate::reality::handshake::connect`] до прикладных ключей, — то, чем
//! наконец несутся байты VLESS.
//!
//! Шифрование здесь двойное, и намеренно: сам VLESS ничего не шифрует, а
//! Reality обязана довести TLS 1.3 до конца, чтобы сервер не отличил её от
//! настоящего сайта, — значит, байты VLESS по умолчанию идут внутри уже
//! зашифрованного канала. Второй слой снимает [`crate::vision`], когда
//! профиль просит `flow = "xtls-rprx-vision"`: он оборачивает этот тип
//! снаружи и, увидев признак переключения, дальше пишет и читает байты
//! напрямую через `RealityStream::io_mut`, минуя [`RecordKey::seal`]/
//! [`RecordKey::open`] этого файла. Без `flow` этот тип работает как и
//! раньше — Vision просто не встаёт между ним и вызывающим.
//!
//! # Чего этот слой не делает
//!
//! - **`KeyUpdate`** (RFC 8446 §4.6.3) не поддержан: если сервер его
//!   пришлёт, чтение обрывается ошибкой
//!   ([`RealityError::KeyUpdateNotSupported`]), а не продолжает молча
//!   работать на ключах, которые сервер уже считает устаревшими.
//! - **`NewSessionTicket`** (RFC 8446 §4.6.1, возобновление сессии) —
//!   единственный кадр, который этот слой отбрасывает без ошибки. Билеты
//!   этой реализацией нигде не хранятся и не предъявляются, а сервер шлёт
//!   их сразу после своего `Finished`, не дожидаясь запроса; отбросить кадр
//!   безопаснее, чем по ошибке принять его за данные VLESS. Не «молча» в
//!   смысле AGENTS.md: вот этот абзац — запись о том, что кадр отброшен, а
//!   не забытый случай.

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

/// Максимальная длина открытого текста одной записи — RFC 8446 §5.1.
const MAX_PLAINTEXT_RECORD: usize = 16_384;

/// `alert` — RFC 8446 §5 (Приложение B.2 у типов содержимого).
const CONTENT_TYPE_ALERT: u8 = 0x15;
/// `NewSessionTicket` — RFC 8446 §B.3.
const HANDSHAKE_TYPE_NEW_SESSION_TICKET: u8 = 4;
/// `KeyUpdate` — RFC 8446 §B.3.
const HANDSHAKE_TYPE_KEY_UPDATE: u8 = 24;

/// Сколько байт брать из сети за раз, пока не набралась целая запись.
const CHUNK: usize = 4 * 1024;

/// Поток VLESS поверх прикладных записей TLS 1.3.
pub struct RealityStream<S> {
    io: S,
    read_key: RecordKey,
    write_key: RecordKey,
    /// Байты с провода, ещё не собранные в целую запись.
    read_raw: BytesMut,
    /// Расшифрованные байты, ещё не отданные читателю.
    read_plain: BytesMut,
    /// Зашифрованная запись, ещё не дописанная целиком в `io`.
    write_pending: BytesMut,
    /// Сколько байт входа `poll_write` уже принял (запечатал в
    /// `write_pending`) — возвращается вызывающему только после того, как
    /// вся запись целиком ушла в `io`.
    write_accepted: usize,
}

impl<S> std::fmt::Debug for RealityStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityStream").finish_non_exhaustive()
    }
}

impl<S> RealityStream<S> {
    /// Оборачивает соединение, доведённое
    /// [`crate::reality::handshake::connect`] до прикладных ключей: `read_key`
    /// расшифровывает то, что шлёт сервер, `write_key` шифрует то, что
    /// уходит ему.
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

    /// Прямой доступ к потоку под записями TLS 1.3 — то, ради чего
    /// [`crate::vision`] вообще существует: как только он видит `Direct`, он
    /// перестаёт звать [`Self::seal`]/[`Self::open`]-обёртку этого типа
    /// (`poll_read`/`poll_write` ниже) и пишет/читает эти байты сюда прямо,
    /// без второго слоя шифрования. До переключения этот метод не зовёт
    /// никто, и канал работает ровно как без Vision.
    pub(crate) fn io_mut(&mut self) -> &mut S {
        &mut self.io
    }

    /// Забирает байты, уже снятые с провода, но ещё не собранные в целую
    /// запись — то, что [`crate::vision`] обязан подобрать в момент
    /// переключения в прямой режим: если сервер прислал первые байты
    /// внутреннего TLS в одном пакете с последней зашифрованной записью, они
    /// уже лежат здесь, а не в TLS-шифротексте, и пытаться расшифровать их
    /// как запись — значит принять чужие данные за повреждённый шифротекст.
    pub(crate) fn take_undecrypted_read_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.read_raw).to_vec()
    }
}

/// Что случилось с одной цельной записью, снятой с провода.
enum RecordOutcome {
    /// Настоящие данные VLESS — отдать читателю.
    ApplicationData(Vec<u8>),
    /// `change_cipher_spec` или `NewSessionTicket` — не данные, но и не
    /// ошибка (см. документ модуля).
    Ignored,
}

/// Снимает с `raw` одну целую TLS-запись, если она уже накопилась, и
/// расшифровывает её. `Ok(None)` — записи ещё не хватает, это обычное дело
/// в потоке, а не ошибка.
fn take_record(
    raw: &mut BytesMut,
    key: &mut RecordKey,
) -> Result<Option<RecordOutcome>, RealityError> {
    if raw.len() < 5 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
    let total = 5 + len;
    if raw.len() < total {
        return Ok(None);
    }

    let header = [raw[0], raw[1], raw[2], raw[3], raw[4]];
    let mut body = raw[5..total].to_vec();
    raw.advance(total);

    match header[0] {
        CONTENT_TYPE_CHANGE_CIPHER_SPEC => return Ok(Some(RecordOutcome::Ignored)),
        CONTENT_TYPE_APPLICATION_DATA => {}
        other => {
            return Err(RealityError::Malformed(format!(
                "тип записи {other:#04x} после рукопожатия — не application_data (0x17)"
            )));
        }
    }

    let (inner_type, plaintext) = key.open(&header, &mut body)?;
    match inner_type {
        CONTENT_TYPE_APPLICATION_DATA => Ok(Some(RecordOutcome::ApplicationData(plaintext))),
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
                    this.read_plain = BytesMut::from(&data[..]);
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
                Poll::Ready(Ok(())) if filled == 0 => return Poll::Ready(Ok(())), // конец потока
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
            let sealed = this
                .write_key
                .seal(CONTENT_TYPE_APPLICATION_DATA, &buf[..take])
                .map_err(as_io)?;
            this.write_pending = BytesMut::from(&sealed[..]);
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

/// Ошибка Reality в языке, на котором говорят [`AsyncRead`] и [`AsyncWrite`].
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

    /// Пара ключей записи для «клиента» и «сервера» одного и того же
    /// поддельного рукопожатия — какие получились бы у обеих сторон, если
    /// бы они вывели их из общего секрета правильно. Тест не проверяет вывод
    /// ключей (это RFC 8448 в `key_schedule.rs`/`record.rs`), только то, что
    /// этот слой правильно нарезает и склеивает записи вокруг них.
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
        let client_write = ticket_key_placeholder(cipher); // клиент здесь не пишет

        let (client_io, mut server_io) = duplex(8192);
        let mut client = RealityStream::new(client_io, client_read, client_write);

        // NewSessionTicket поддельного сервера — тип рукопожатия 0x04. Оба
        // кадра шлёт один и тот же ключ записи, по порядку (seq 0, потом 1)
        // — как и было бы у настоящего сервера в одном потоке.
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

    /// `RecordKey` не умеет клонироваться (и не должен): для теста выше
    /// нужен ключ записи для стороны, которая ничего не пишет, — этот же
    /// шифр и ключ, что и у "сервера", читающего `ticket`.
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

        // KeyUpdate — тип рукопожатия 0x18, тело не разбирается до отказа.
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
