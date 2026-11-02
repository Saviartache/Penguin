//! `CONNECT` по уже открытому потоку.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{I2pError, I2pResult};
use crate::response::{HEAD_END, HEAD_LIMIT, connect_request, status_code};

/// Шлёт `CONNECT` и возвращает код ответа; поток после него — канал до `authority`.
pub async fn connect<S>(io: &mut S, authority: &str) -> I2pResult<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    io.write_all(&connect_request(authority)).await?;
    io.flush().await?;
    let head = read_head(io).await?;
    status_code(&head)
}

/// Читает заголовок по байту: прочитанное сверх него принадлежало бы приложению.
async fn read_head<S: AsyncRead + Unpin>(io: &mut S) -> I2pResult<Vec<u8>> {
    let mut head = Vec::with_capacity(128);
    while !head.ends_with(HEAD_END) {
        if head.len() >= HEAD_LIMIT {
            return Err(I2pError::Malformed(format!(
                "заголовок длиннее {HEAD_LIMIT} байт"
            )));
        }
        head.push(io.read_u8().await?);
    }
    Ok(head)
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    #[tokio::test]
    async fn bytes_after_the_head_stay_in_the_stream() {
        let (mut client, mut server) = duplex(1024);
        let serve = tokio::spawn(async move {
            let mut request = vec![0; 64];
            let n = server.read(&mut request).await.expect("запрос");
            server
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nSSH-2.0-banner")
                .await
                .expect("ответ");
            request.truncate(n);
            request
        });

        assert_eq!(
            connect(&mut client, "example.com:22").await.expect("200"),
            200
        );
        let mut banner = [0; 14];
        client.read_exact(&mut banner).await.expect("баннер");
        assert_eq!(&banner, b"SSH-2.0-banner");
        assert!(
            serve
                .await
                .expect("сервер")
                .starts_with(b"CONNECT example.com:22 ")
        );
    }

    #[tokio::test]
    async fn a_closed_proxy_is_an_io_error() {
        let (mut client, server) = duplex(64);
        drop(server);
        assert!(matches!(
            connect(&mut client, "example.com:443").await,
            Err(I2pError::Io(_))
        ));
    }
}
