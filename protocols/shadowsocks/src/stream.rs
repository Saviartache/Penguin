//! Поток, зашифрованный целиком.
//!
//! ```text
//!  ──► [соль] [длина+метка] [кусок+метка] [длина+метка] [кусок+метка] ...
//!       ^^^^^^
//!       открытым текстом, один раз в начале
//! ```
//!
//! Заголовков у Shadowsocks нет вовсе: с первого байта после соли идёт шифр.
//! Адрес назначения — тоже внутри, первым куском, и снаружи его не видно.
//!
//! # Отчего здесь так мало
//!
//! Кадр — соль, длина отдельным сообщением, кусок следующим — у Shadowsocks
//! общий со Snell, и живёт он в [`penguin_transport::aead`]. Своим у
//! протокола остался только вывод ключа, и он передаётся туда через
//! [`penguin_transport::aead::Keying`].
//!
//! Тесты, однако, остались здесь. Общий кадр проверяется у себя на выдуманном
//! выводе ключа; здесь — на настоящем, том самом, которым говорит сервер.

use penguin_transport::aead::{ChunkStream, Cipher, Keying};

pub use penguin_transport::aead::{MAX_CHUNK, seal_chunk};

/// Поток Shadowsocks поверх обычного соединения.
pub type SsStream<S> = ChunkStream<S>;

/// Оборачивает соединение, в которое уже отправлены соль и адрес.
pub fn wrap<S>(io: S, keying: Keying, send: Cipher) -> SsStream<S> {
    ChunkStream::new(io, keying, send)
}

#[cfg(test)]
mod tests {
    use std::io;

    use penguin_transport::aead::{TAG_LEN, sealed_len};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::crypto::kdf;
    use crate::crypto::method::Method;

    /// Сколько байт занимает зашифрованная длина: два байта и метка.
    const LENGTH_FRAME: usize = 2 + TAG_LEN;

    const METHOD: Method = Method::Aes256Gcm;
    const PASSWORD: &str = "пароль от сервера";

    /// Собирает пару «клиент, сервер» с общим паролем.
    ///
    /// Сервер здесь ненастоящий: он умеет только то же, что клиент, — и это
    /// ровно то, что нужно, чтобы проверить кадры без сети.
    fn pair() -> (
        SsStream<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
        Vec<u8>,
    ) {
        let (client, server) = duplex(1024 * 1024);
        let master = kdf::master_key(PASSWORD, METHOD);

        let salt = vec![3u8; METHOD.salt_len()];
        let key = kdf::session_key(&master, &salt, METHOD).expect("выводится");
        let send = Cipher::new(METHOD.algorithm(), &key).expect("ключ подходит");

        (
            wrap(client, kdf::keying(master.clone(), METHOD), send),
            server,
            master,
        )
    }

    /// Собирает то, что прислал бы сервер: свою соль и куски под ней.
    fn from_server(master: &[u8], pieces: &[&[u8]]) -> Vec<u8> {
        let salt = vec![9u8; METHOD.salt_len()];
        let key = kdf::session_key(master, &salt, METHOD).expect("выводится");
        let mut cipher = Cipher::new(METHOD.algorithm(), &key).expect("ключ подходит");

        let mut out = salt;
        for piece in pieces {
            out.extend_from_slice(&seal_chunk(&mut cipher, piece).expect("шифруется"));
        }
        out
    }

    #[tokio::test]
    async fn what_the_server_sends_arrives_whole() {
        let (mut client, mut server, master) = pair();
        server
            .write_all(&from_server(&master, &[b"first ", b"second"]))
            .await
            .expect("ушло");

        let mut got = [0u8; 12];
        client.read_exact(&mut got).await.expect("пришло");
        assert_eq!(&got, b"first second");
    }

    #[tokio::test]
    async fn a_reply_arriving_in_pieces_is_assembled() {
        // Соль, длина и кусок приезжают тремя пакетами — обычное дело.
        let (mut client, mut server, master) = pair();
        let wire = from_server(&master, &[b"payload"]);

        let reader = tokio::spawn(async move {
            let mut got = [0u8; 7];
            client.read_exact(&mut got).await.expect("пришло");
            got
        });

        for byte in wire {
            server.write_all(&[byte]).await.expect("ушло");
        }
        assert_eq!(&reader.await.expect("задача"), b"payload");
    }

    #[tokio::test]
    async fn a_wrong_password_looks_like_a_refusal() {
        // Отказа у Shadowsocks нет: сервер с другим паролем просто пришлёт то,
        // что у нас не расшифруется. Это и есть «неверный пароль».
        let (mut client, mut server, _) = pair();
        let other = kdf::master_key("другой пароль", METHOD);
        server
            .write_all(&from_server(&other, &[b"payload"]))
            .await
            .expect("ушло");

        let mut got = [0u8; 7];
        let err = client.read_exact(&mut got).await.expect_err("не сошлось");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("метка подлинности"), "{err}");
    }

    #[tokio::test]
    async fn a_changed_byte_is_noticed() {
        let (mut client, mut server, master) = pair();
        let mut wire = from_server(&master, &[b"payload"]);
        let last = wire.len() - 1;
        wire[last] ^= 1;
        server.write_all(&wire).await.expect("ушло");

        let mut got = [0u8; 7];
        assert!(client.read_exact(&mut got).await.is_err());
    }

    #[tokio::test]
    async fn a_stream_cut_mid_chunk_is_an_error() {
        let (mut client, mut server, master) = pair();
        let wire = from_server(&master, &[b"payload"]);
        server
            .write_all(&wire[..wire.len() - 3])
            .await
            .expect("ушло");
        drop(server);

        let mut got = Vec::new();
        let err = client.read_to_end(&mut got).await.expect_err("оборвано");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_server_that_says_nothing_is_a_clean_end() {
        // Сервер вправе закрыть соединение, не прислав даже соли.
        let (mut client, server, _) = pair();
        drop(server);

        let mut got = Vec::new();
        client.read_to_end(&mut got).await.expect("чистый конец");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn an_absurd_length_is_refused() {
        // Больше предела протокол не допускает: на том конце не Shadowsocks.
        let (mut client, mut server, master) = pair();

        let salt = vec![9u8; METHOD.salt_len()];
        let key = kdf::session_key(&master, &salt, METHOD).expect("выводится");
        let mut cipher = Cipher::new(METHOD.algorithm(), &key).expect("ключ подходит");

        let mut wire = salt;
        wire.extend_from_slice(&cipher.seal(&0xFFFFu16.to_be_bytes()).expect("шифруется"));
        server.write_all(&wire).await.expect("ушло");

        let mut got = [0u8; 1];
        let err = client
            .read_exact(&mut got)
            .await
            .expect_err("не по протоколу");
        assert!(err.to_string().contains("такого не допускает"), "{err}");
    }

    #[tokio::test]
    async fn a_long_write_is_cut_into_chunks() {
        // Длина пишется двумя байтами с запасом на служебные биты: кусок
        // длиннее предела сервер не примет.
        let (mut client, mut server, _) = pair();
        let payload = vec![7u8; MAX_CHUNK + 1000];

        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.expect("ушло");
            client.flush().await.expect("сброшено");
        });

        // Первый кусок — ровно предел, второй — остаток.
        let mut head = vec![0u8; LENGTH_FRAME];
        server.read_exact(&mut head).await.expect("пришло");
        let mut body = vec![0u8; sealed_len(MAX_CHUNK)];
        server.read_exact(&mut body).await.expect("пришло");

        let mut head = vec![0u8; LENGTH_FRAME];
        server.read_exact(&mut head).await.expect("пришло");
        let mut body = vec![0u8; sealed_len(1000)];
        server.read_exact(&mut body).await.expect("пришло");

        writer.await.expect("задача");
    }
}
