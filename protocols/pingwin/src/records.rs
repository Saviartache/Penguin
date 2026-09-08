//! Записи на проводе: чтение и запись с шифрованием и дополнением.
//!
//! Тонкий слой между сокетом и мультиплексором. Всё, что он знает, — как
//! превратить набор кадров в запись и обратно; про потоки, адреса и сессии он
//! не знает ничего.
//!
//! # Почему счётчик записей живёт здесь
//!
//! Дополнение считается по номеру записи ([`crate::wire::padding`]), а номер
//! знает только тот, кто эти записи пишет. Отдать счётчик выше означало бы
//! договариваться о нём между всеми, кто пишет в сессию, — а пишут в неё все
//! потоки сразу.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use penguin_transport::aead::Cipher;

use crate::error::{PingwinError, PingwinResult};
use crate::wire::padding::{self, Padding};
use crate::wire::record;

/// Сколько читать из сокета за раз.
///
/// Без буфера каждая запись — это два системных вызова (заголовок и тело), и
/// на быстрой загрузке их получаются десятки тысяч в секунду. Четыре записи
/// за раз — это одно чтение вместо восьми.
const READ_BUFFER: usize = 4 * record::MAX_BODY;

/// Читающая половина.
pub struct RecordReader<R> {
    io: BufReader<R>,
    cipher: Cipher,
}

impl<R: AsyncRead + Unpin> RecordReader<R> {
    /// Оборачивает читающую половину соединения.
    pub fn new(io: R, cipher: Cipher) -> Self {
        Self {
            io: BufReader::with_capacity(READ_BUFFER, io),
            cipher,
        }
    }

    /// Читает следующую запись данных и расшифровывает её.
    ///
    /// Записи не с данными (`ChangeCipherSpec`) пропускаются: настоящий TLS
    /// шлёт их ради совместимости, и наш собеседник — тоже. Отвергать их
    /// значило бы рвать соединение из-за шести байт, которые ничего не несут.
    pub async fn read(&mut self) -> PingwinResult<Vec<u8>> {
        loop {
            let mut header = [0u8; record::HEADER_LEN];
            self.io.read_exact(&mut header).await.map_err(closed)?;
            let (content_type, len) = record::parse_header(&header)?;

            let mut body = vec![0u8; len];
            self.io.read_exact(&mut body).await.map_err(closed)?;

            if content_type != record::CONTENT_DATA {
                continue;
            }
            let plain = record::open(&mut self.cipher, &mut body)?;
            body.truncate(plain);
            return Ok(body);
        }
    }
}

impl<R> std::fmt::Debug for RecordReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordReader").finish_non_exhaustive()
    }
}

/// Пишущая половина.
pub struct RecordWriter<W> {
    io: W,
    cipher: Cipher,
    padding: Padding,
    /// Номер следующей записи — по нему берётся длина дополнения.
    index: usize,
}

impl<W: AsyncWrite + Unpin> RecordWriter<W> {
    /// Оборачивает пишущую половину соединения.
    pub fn new(io: W, cipher: Cipher, padding: Padding) -> Self {
        Self {
            io,
            cipher,
            padding,
            index: 0,
        }
    }

    /// Дополняет, зашифровывает и отправляет набор кадров одной записью.
    ///
    /// `frames` расходуется: дополнение дописывается прямо в него, чтобы не
    /// копировать килобайт на каждую запись.
    pub async fn write(&mut self, frames: &mut Vec<u8>) -> PingwinResult<()> {
        padding::pad(frames, self.padding.target(self.index));
        self.index = self.index.saturating_add(1);

        let mut wire = Vec::with_capacity(record::HEADER_LEN + frames.len() + 16);
        record::seal(&mut self.cipher, frames, &mut wire)?;
        self.io.write_all(&wire).await?;
        self.io.flush().await?;
        Ok(())
    }

    /// Закрывает пишущую половину.
    pub async fn shutdown(&mut self) -> PingwinResult<()> {
        Ok(self.io.shutdown().await?)
    }
}

impl<W> std::fmt::Debug for RecordWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordWriter")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// Обрыв на чтении — это не «ошибка ввода-вывода», а закрытое соединение.
///
/// Разница видна `supervisor`: обрыв повторяют, а ошибку настроек — нет.
fn closed(err: std::io::Error) -> PingwinError {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        return PingwinError::disconnected("собеседник закрыл соединение");
    }
    PingwinError::Io(err)
}

#[cfg(test)]
mod tests {
    use penguin_transport::aead::Algorithm;
    use tokio::io::duplex;

    use super::*;
    use crate::wire::frame;

    fn cipher() -> Cipher {
        Cipher::new(Algorithm::Aes256Gcm, &[5u8; 32]).expect("ключ подходит")
    }

    #[tokio::test]
    async fn frames_survive_the_trip_through_a_record() {
        let (client, server) = duplex(64 * 1024);
        let mut writer = RecordWriter::new(client, cipher(), Padding::none());
        let mut reader = RecordReader::new(server, cipher());

        let mut frames = frame::encode(frame::DATA, 1, b"payload").expect("собирается");
        writer.write(&mut frames).await.expect("записалось");

        let plain = reader.read().await.expect("прочиталось");
        let (header, body) = frame::Frames::new(&plain)
            .next()
            .expect("кадр есть")
            .expect("разбирается");
        assert_eq!(header.cmd, frame::DATA);
        assert_eq!(body, b"payload");
    }

    #[tokio::test]
    async fn padding_changes_the_length_on_the_wire_but_not_the_frames() {
        let (client, server) = duplex(64 * 1024);
        let seed = [0x3Cu8; 32];
        let mut writer = RecordWriter::new(client, cipher(), Padding::from_seed(&seed));
        let mut reader = RecordReader::new(server, cipher());

        let mut frames = frame::encode(frame::DATA, 1, b"hi").expect("собирается");
        writer.write(&mut frames).await.expect("записалось");

        let plain = reader.read().await.expect("прочиталось");
        assert_eq!(plain.len(), Padding::from_seed(&seed).target(0));

        let frames: Vec<_> = frame::Frames::new(&plain)
            .map(|f| f.expect("разбирается"))
            .collect();
        assert_eq!(frames[0].1, b"hi");
        assert_eq!(frames[1].0.cmd, frame::PAD);
    }

    #[tokio::test]
    async fn a_change_cipher_spec_record_is_stepped_over() {
        // Настоящий TLS 1.3 шлёт её ради мидлбоксов, и наш собеседник тоже:
        // рвать из-за неё соединение значило бы не уметь читать себя же.
        let (mut client, server) = duplex(64 * 1024);
        let mut reader = RecordReader::new(server, cipher());

        let mut wire = record::CHANGE_CIPHER_SPEC.to_vec();
        let frames = frame::encode(frame::PING, 0, &[]).expect("собирается");
        record::seal(&mut cipher(), &frames, &mut wire).expect("шифруется");
        client.write_all(&wire).await.expect("записалось");

        let plain = reader.read().await.expect("прочиталось");
        assert_eq!(
            frame::Frames::new(&plain)
                .next()
                .expect("кадр есть")
                .expect("разбирается")
                .0
                .cmd,
            frame::PING
        );
    }

    #[tokio::test]
    async fn a_closed_connection_is_a_disconnect_not_an_io_error() {
        // От этого зависит, будет ли `supervisor` пробовать снова.
        let (client, server) = duplex(64);
        drop(client);
        let mut reader = RecordReader::new(server, cipher());
        assert!(matches!(
            reader.read().await,
            Err(PingwinError::Disconnected(_))
        ));
    }

    #[tokio::test]
    async fn a_record_sealed_with_another_key_is_refused() {
        // Метка AEAD заверяет запись целиком: не сошлась — значит, либо не тот
        // пароль, либо правка по дороге.
        let (client, server) = duplex(64 * 1024);
        let mut writer = RecordWriter::new(client, cipher(), Padding::none());
        let other = Cipher::new(Algorithm::Aes256Gcm, &[6u8; 32]).expect("ключ подходит");
        let mut reader = RecordReader::new(server, other);

        let mut frames = frame::encode(frame::PING, 0, &[]).expect("собирается");
        writer.write(&mut frames).await.expect("записалось");
        assert!(reader.read().await.is_err());
    }
}
