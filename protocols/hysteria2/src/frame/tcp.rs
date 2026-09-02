//! TCPRequest и TCPResponse.
//!
//! ```text
//! TCPRequest                        TCPResponse
//! ┌───────────────────────┐         ┌───────────────────────┐
//! │ varint  0x401         │         │ u8      статус        │
//! │ varint  длина адреса  │         │ varint  длина текста  │
//! │ bytes   адрес         │         │ bytes   текст         │
//! │ varint  длина допол-я │         │ varint  длина допол-я │
//! │ bytes   дополнение    │         │ bytes   дополнение    │
//! └───────────────────────┘         └───────────────────────┘
//! ```
//!
//! Запрос уходит в новый двунаправленный поток QUIC, ответ приходит по нему же.

use std::io;

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::padding::{MAX_MESSAGE_LENGTH, MAX_PADDING_LENGTH, Padding};
use super::varint;

/// Номер кадра запроса на TCP-соединение.
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// Ответ: соединение установлено.
pub const STATUS_OK: u8 = 0x00;

/// Собирает запрос на соединение с указанным адресом.
///
/// Адрес — строка `host:port`, и хост в ней вполне может быть доменом:
/// разрешать его будет сервер. В этом и смысл — иначе правила по доменам
/// работали бы только до первого обращения к DNS.
pub fn encode_request(address: &str) -> BytesMut {
    let padding = Padding::TCP_REQUEST.generate();
    let capacity = varint::encoded_len(FRAME_TYPE_TCP_REQUEST)
        + varint::encoded_len(address.len() as u64)
        + address.len()
        + varint::encoded_len(padding.len() as u64)
        + padding.len();

    let mut buf = BytesMut::with_capacity(capacity);
    varint::encode(FRAME_TYPE_TCP_REQUEST, &mut buf);
    varint::encode(address.len() as u64, &mut buf);
    buf.put_slice(address.as_bytes());
    varint::encode(padding.len() as u64, &mut buf);
    buf.put_slice(padding.as_bytes());
    buf
}

/// Ответ сервера на запрос соединения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResponse {
    /// Соединение установлено.
    pub ok: bool,
    /// Пояснение сервера. При отказе — причина; при успехе обычно пусто.
    pub message: String,
}

/// Читает ответ из потока.
///
/// Дополнение вычитывается и отбрасывается: без этого следующие за ним байты
/// уехали бы в прикладной поток, и соединение начало бы отдавать мусор
/// вместо данных.
pub async fn read_response<R>(reader: &mut R) -> io::Result<TcpResponse>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let status = reader.read_u8().await?;

    let message_len = varint::read_from(reader).await?;
    if message_len > MAX_MESSAGE_LENGTH {
        return Err(too_long("длина сообщения", message_len, MAX_MESSAGE_LENGTH));
    }
    let mut message = vec![0u8; message_len as usize];
    reader.read_exact(&mut message).await?;

    let padding_len = varint::read_from(reader).await?;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(too_long(
            "длина дополнения",
            padding_len,
            MAX_PADDING_LENGTH,
        ));
    }
    skip(reader, padding_len as usize).await?;

    Ok(TcpResponse {
        ok: status == STATUS_OK,
        message: String::from_utf8_lossy(&message).into_owned(),
    })
}

/// Вычитывает и отбрасывает указанное число байт.
///
/// Буфером по 512 байт, а не выделением на всю длину: длина пришла с той
/// стороны, и выделять по ней память — приглашение исчерпать её чужим числом.
async fn skip<R>(reader: &mut R, mut remaining: usize) -> io::Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut scratch = [0u8; 512];
    while remaining > 0 {
        let take = remaining.min(scratch.len());
        reader.read_exact(&mut scratch[..take]).await?;
        remaining -= take;
    }
    Ok(())
}

fn too_long(what: &str, got: u64, limit: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{what}: {got} превышает предел {limit}"),
    )
}

#[cfg(test)]
mod tests {
    use bytes::Buf;

    use super::*;

    #[test]
    fn request_layout_matches_spec() {
        let encoded = encode_request("example.com:443");
        let mut reading = encoded.freeze();

        assert_eq!(varint::decode(&mut reading), Some(FRAME_TYPE_TCP_REQUEST));

        let addr_len = varint::decode(&mut reading).expect("длина адреса") as usize;
        assert_eq!(addr_len, "example.com:443".len());
        let addr = reading.split_to(addr_len);
        assert_eq!(&addr[..], b"example.com:443");

        let padding_len = varint::decode(&mut reading).expect("длина дополнения") as usize;
        assert_eq!(reading.remaining(), padding_len);
        assert!((64..=512).contains(&padding_len));
    }

    #[test]
    fn request_keeps_domain_unresolved() {
        // Домен обязан уехать на сервер как есть: разрешать его здесь —
        // значит потерять имя, по которому работают правила.
        let encoded = encode_request("youtube.com:443");
        assert!(encoded.windows(15).any(|w| w == b"youtube.com:443"));
    }

    fn response_bytes(status: u8, message: &str, padding: &str) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u8(status);
        varint::encode(message.len() as u64, &mut buf);
        buf.put_slice(message.as_bytes());
        varint::encode(padding.len() as u64, &mut buf);
        buf.put_slice(padding.as_bytes());
        buf.to_vec()
    }

    #[tokio::test]
    async fn reads_successful_response() {
        let bytes = response_bytes(STATUS_OK, "", "xxxxx");
        let mut reader = std::io::Cursor::new(bytes);
        let response = read_response(&mut reader).await.expect("читается");
        assert!(response.ok);
        assert!(response.message.is_empty());
    }

    #[tokio::test]
    async fn reads_failure_with_message() {
        let bytes = response_bytes(0x01, "connection refused", "pad");
        let mut reader = std::io::Cursor::new(bytes);
        let response = read_response(&mut reader).await.expect("читается");
        assert!(!response.ok);
        assert_eq!(response.message, "connection refused");
    }

    #[tokio::test]
    async fn consumes_padding_entirely() {
        // После ответа в потоке должны остаться только прикладные данные.
        let mut bytes = response_bytes(STATUS_OK, "", "0123456789");
        bytes.extend_from_slice(b"HTTP/1.1 200 OK");
        let mut reader = std::io::Cursor::new(bytes);
        read_response(&mut reader).await.expect("читается");

        let mut rest = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut rest)
            .await
            .expect("хвост");
        assert_eq!(rest, b"HTTP/1.1 200 OK");
    }

    #[tokio::test]
    async fn rejects_absurd_lengths() {
        // Длина пришла с той стороны — выделять по ней память нельзя.
        let mut buf = BytesMut::new();
        buf.put_u8(STATUS_OK);
        varint::encode(1_000_000, &mut buf);
        let mut reader = std::io::Cursor::new(buf.to_vec());
        assert!(read_response(&mut reader).await.is_err());
    }
}
