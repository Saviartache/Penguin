//! Кадрирование сообщений: длина и тело.
//!
//! Канал управления потоковый: границ сообщений в нём нет, и без явной длины
//! получатель не знает, где кончается один запрос и начинается следующий.
//!
//! ```text
//!   ┌──────────┬─────────────────────┐
//!   │ длина u32│ тело JSON           │
//!   │  4 байта │ длина байт          │
//!   └──────────┴─────────────────────┘
//! ```
//!
//! Тело в JSON, а не в двоичном формате. Причина не в лени: канал управления
//! — не горячий путь, сообщений по нему единицы в секунду, зато отладка
//! глазами и совместимость между версиями стоят дорого. Двоичный формат
//! сэкономил бы микросекунды и отнял бы возможность прочитать, что пошло не
//! так.

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{IpcError, IpcResult};

/// Наибольший размер сообщения.
///
/// Самое крупное, что ходит по каналу, — настройки целиком: десятки
/// килобайт. Мегабайт с запасом, и он же не даёт чужому процессу заказать
/// выделение памяти произвольного размера одним числом в заголовке.
pub const MAX_MESSAGE: usize = 1024 * 1024;

/// Отправляет сообщение.
pub async fn write<W, T>(writer: &mut W, message: &T) -> IpcResult<()>
where
    W: AsyncWrite + Unpin + ?Sized,
    T: Serialize,
{
    let body = serde_json::to_vec(message)?;

    if body.len() > MAX_MESSAGE {
        return Err(IpcError::TooLarge {
            size: body.len(),
            limit: MAX_MESSAGE,
        });
    }

    // Длина и тело одной записью: две отдельные записи разошлись бы по
    // пакетам, и получатель ждал бы тело, которое ещё в пути.
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
    framed.extend_from_slice(&body);

    writer.write_all(&framed).await?;
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

    // Длина пришла с той стороны; выделять по ней память без проверки —
    // приглашение исчерпать её одним числом.
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
        // Ради этого длина и нужна: без неё второе сообщение слилось бы с
        // первым.
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
        // Число в заголовке приходит с той стороны; выделять по нему память
        // без проверки нельзя.
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
