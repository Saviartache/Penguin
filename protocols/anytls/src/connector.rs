//! Как заводится соединение до сервера: TLS и опознание.
//!
//! Опознание — первое, что уходит после рукопожатия TLS, и уходит оно одной
//! записью:
//!
//! ```text
//!  +--------------------+--------+------------+
//!  |  SHA-256(пароль)   | длина  | дополнение |
//!  +--------------------+--------+------------+
//!  |      32 байта      | 2 (BE) |   нули     |
//!  +--------------------+--------+------------+
//! ```
//!
//! Длина дополнения — это размер, назначенный схемой пакету `0`. Обратите
//! внимание: здесь число из схемы означает длину **дополнения**, а не всей
//! записи, — в отличие от пакета `1` и дальше. Так у эталона, и запись
//! опознания выходит на 34 байта длиннее числа из схемы.
//!
//! Ответа на опознание нет. Узнал сервер отпечаток или не узнал, видно
//! только по тому, продолжит ли он разговор.

use std::sync::Arc;

use penguin_core::address::Address;
use penguin_proto::connect;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;
use penguin_transport::deadline;
use penguin_transport::tls::TlsClient;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::config::AnyTlsConfig;
use crate::error::{AnyTlsError, AnyTlsResult};
use crate::padding::{Padding, Step};

/// Длина отпечатка пароля.
pub const HASH_LEN: usize = 32;

/// Как открывать соединения к серверу.
pub struct Connector {
    host: Address,
    port: u16,
    tls: TlsClient,
    dialer: Arc<dyn Dialer>,
    /// Отпечаток пароля: считается один раз, а не на каждую сессию.
    password: [u8; HASH_LEN],
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish()
    }
}

impl Connector {
    /// Собирает соединитель. Соединения при этом не открывается.
    pub fn new(config: &AnyTlsConfig, dialer: Arc<dyn Dialer>) -> AnyTlsResult<Self> {
        let (host, port) = config.endpoint()?;
        let tls = TlsClient::new(&config.tls, &host, config.default_alpn())?;
        Ok(Self {
            host,
            port,
            tls,
            dialer,
            password: password_hash(&config.password),
        })
    }

    /// Открывает соединение и опознаётся на нём.
    pub async fn connect(&self, padding: &Padding) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let plain = connect::dial(&*self.dialer, &self.host, self.port).await?;
        let mut secure = self.tls.connect(plain).await.map_err(AnyTlsError::from)?;

        let hello = hello(&self.password, padding_len(padding));
        deadline::handshake::<_, AnyTlsError>("опознание AnyTLS", async {
            secure.write_all(&hello).await?;
            secure.flush().await?;
            Ok(())
        })
        .await?;

        Ok(Box::new(secure))
    }
}

/// Отпечаток пароля.
pub fn password_hash(password: &str) -> [u8; HASH_LEN] {
    Sha256::digest(password.as_bytes()).into()
}

/// Собирает запись опознания.
pub fn hello(password: &[u8; HASH_LEN], padding: usize) -> Vec<u8> {
    let padding = padding.min(crate::padding::MAX_SIZE);
    let mut out = Vec::with_capacity(HASH_LEN + 2 + padding);
    out.extend_from_slice(password);
    out.extend_from_slice(&(padding as u16).to_be_bytes());
    out.resize(HASH_LEN + 2 + padding, 0);
    out
}

/// Сколько байт дополнения приложить к опознанию.
///
/// Берётся первый **размер** из схемы, а не первое правило: схема вправе
/// начинаться с проверки, и эталон в этом случае объявил бы длину в 65535
/// байт, которых не пришлёт. Ноль честнее.
fn padding_len(padding: &Padding) -> usize {
    padding
        .get()
        .steps(0)
        .into_iter()
        .find_map(|step| match step {
            Step::Size(size) => Some(size),
            Step::Check => None,
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding::Padding;

    #[test]
    fn the_hello_is_the_shape_the_reference_reads() {
        let hello = hello(&password_hash("secret"), 30);
        assert_eq!(hello.len(), 32 + 2 + 30);
        assert_eq!(&hello[32..34], &30_u16.to_be_bytes());
        assert!(
            hello[34..].iter().all(|byte| *byte == 0),
            "дополнение не нули"
        );
    }

    #[test]
    fn the_default_scheme_asks_for_thirty_bytes() {
        // Отсюда и берётся «накладные расходы опознания — 34 байта»: запись
        // выходит ровно в 64 байта.
        let padding = Padding::new();
        assert_eq!(padding_len(&padding), 30);
        assert_eq!(hello(&password_hash("x"), padding_len(&padding)).len(), 64);
    }

    #[test]
    fn a_scheme_that_starts_with_a_check_asks_for_nothing() {
        // Эталон объявил бы здесь 65535 байт, которых не пришлёт, и сервер
        // ждал бы их до срока.
        let padding = Padding::new();
        assert!(padding.update(b"stop=2\n0=c"));
        assert_eq!(padding_len(&padding), 0);
    }

    #[test]
    fn the_fingerprint_is_sha256_and_not_the_password() {
        let hash = password_hash("secret");
        assert_eq!(hash.len(), 32);
        assert_ne!(&hash[..6], "secret".as_bytes());

        // Тот же пароль — тот же отпечаток: сервер сверяет ровно его.
        assert_eq!(hash, password_hash("secret"));
        assert_ne!(hash, password_hash("secre"));
    }
}
