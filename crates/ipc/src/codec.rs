//! Кадр: длина u32 (big-endian) и тело JSON. Канал не горячий, а JSON читается глазами.

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{IpcError, IpcResult};

/// Наибольший размер сообщения; ограничивает выделение по числу из заголовка.
pub const MAX_MESSAGE: usize = 1024 * 1024;

/// Отправляет сообщение одной записью.
pub async fn write<W, T>(writer: &mut W, message: &T) -> IpcResult<()>
where
    W: AsyncWrite + Unpin + ?Sized,
    T: Serialize,
{
    let mut frame = vec![0u8; 4];
    serde_json::to_writer(&mut frame, message)?;

    let size = frame.len() - 4;
    if size > MAX_MESSAGE {
        return Err(IpcError::TooLarge {
            size,
            limit: MAX_MESSAGE,
        });
    }
    frame[..4].copy_from_slice(&(size as u32).to_be_bytes());

    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

/// Читает сообщение.
pub async fn read<R, T>(reader: &mut R) -> IpcResult<T>
where
    R: AsyncRead + Unpin + ?Sized,
    T: DeserializeOwned,
{
    let mut length = [0u8; 4];
    reader.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;

    if length > MAX_MESSAGE {
        return Err(IpcError::TooLarge {
            size: length,
            limit: MAX_MESSAGE,
        });
    }
    if length == 0 {
        return Err(IpcError::Malformed("пустое сообщение".to_owned()));
    }

    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Sample {
        name: String,
        value: u32,
    }

    fn sample() -> Sample {
        Sample {
            name: "привет".to_owned(),
            value: 42,
        }
    }

    #[tokio::test]
    async fn round_trips() {
        let (mut ours, mut theirs) = tokio::io::duplex(4096);
        write(&mut ours, &sample()).await.expect("записано");

        let back: Sample = read(&mut theirs).await.expect("прочитано");
        assert_eq!(back, sample());
    }

    #[tokio::test]
    async fn several_messages_do_not_run_together() {
        let (mut ours, mut theirs) = tokio::io::duplex(8192);
        for value in 0..5u32 {
            write(
                &mut ours,
                &Sample {
                    name: format!("№{value}"),
                    value,
                },
            )
            .await
            .expect("записано");
        }

        for value in 0..5u32 {
            let back: Sample = read(&mut theirs).await.expect("прочитано");
            assert_eq!(back.value, value);
        }
    }

    #[tokio::test]
    async fn oversized_declaration_is_refused() {
        let (mut ours, mut theirs) = tokio::io::duplex(64);
        ours.write_all(&u32::MAX.to_be_bytes())
            .await
            .expect("записано");

        let result: IpcResult<Sample> = read(&mut theirs).await;
        assert!(matches!(result, Err(IpcError::TooLarge { .. })));
    }

    #[tokio::test]
    async fn empty_message_is_refused() {
        let (mut ours, mut theirs) = tokio::io::duplex(64);
        ours.write_all(&0u32.to_be_bytes()).await.expect("записано");

        let result: IpcResult<Sample> = read(&mut theirs).await;
        assert!(matches!(result, Err(IpcError::Malformed(_))));
    }

    #[tokio::test]
    async fn truncated_stream_is_an_error_not_a_hang() {
        let (mut ours, mut theirs) = tokio::io::duplex(64);
        ours.write_all(&100u32.to_be_bytes())
            .await
            .expect("записано");
        ours.write_all("половина".as_bytes())
            .await
            .expect("записано");
        drop(ours);

        let result: IpcResult<Sample> = read(&mut theirs).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn garbage_body_is_reported_clearly() {
        let (mut ours, mut theirs) = tokio::io::duplex(64);
        ours.write_all(&5u32.to_be_bytes()).await.expect("записано");
        ours.write_all("мусор".as_bytes()).await.expect("записано");

        let result: IpcResult<Sample> = read(&mut theirs).await;
        assert!(result.is_err());
    }
}
