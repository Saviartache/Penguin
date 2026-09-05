//! Как заводится соединение: сокет, обфускация, соль и заголовок.
//!
//! ```text
//!  сокет ─► обфускация ─► [соль][заголовок в первом куске] ─► поток
//! ```
//!
//! Соль и заголовок уходят **одной записью**: два пакета там, где протокол
//! шлёт один, видны по дороге. По той же причине обфускация ложится снизу —
//! она обязана увидеть первую запись целиком, чтобы спрятать её в запрос или
//! в приветствие.

use std::sync::Arc;

use penguin_core::address::Address;
use penguin_proto::connect;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;
use penguin_transport::aead::{ChunkStream, Keying, seal_chunk};
use penguin_transport::deadline;
use penguin_transport::obfs::{HttpObfs, Mode, TlsObfs};
use rand::Rng;
use tokio::io::AsyncWriteExt;

use crate::chunks::Chunks;
use crate::config::SnellConfig;
use crate::crypto::{self, SALT_LEN};
use crate::error::{SnellError, SnellResult};
use crate::v4::V4Stream;

/// Поток, каким его видит протокол: куски под общим кадром.
pub type Chunked = ChunkStream<Box<dyn ProxyStream>>;

/// Поток четвёртой версии: свой кадр вместо общего.
pub type Framed = V4Stream<Box<dyn ProxyStream>>;

/// Открытый поток. Какой именно — решает версия.
///
/// Наружу оба одинаковы: и байты, и куски у них есть. Различаются они тем,
/// как эти куски выглядят на проводе, и знать об этом дальше протокола
/// незачем.
pub enum Opened {
    /// Общий кадр: версии с первой по третью.
    Chunks(Chunked),
    /// Свой кадр: четвёртая и пятая.
    Framed(Framed),
}

impl Opened {
    /// Поток байт для приложения.
    pub fn into_stream(self) -> Box<dyn ProxyStream> {
        match self {
            Self::Chunks(io) => Box::new(io),
            Self::Framed(io) => Box::new(io),
        }
    }

    /// Поток кусков для датаграмм.
    pub fn into_chunks(self) -> Box<dyn Chunks> {
        match self {
            Self::Chunks(io) => Box::new(io),
            Self::Framed(io) => Box::new(io),
        }
    }
}

/// Как открывать соединения к серверу.
pub struct Connector {
    config: SnellConfig,
    dialer: Arc<dyn Dialer>,
    /// Хост сервера, разобранный один раз при сборке.
    host: Address,
    /// Порт сервера.
    port: u16,
    /// Вывод ключа: собирается один раз, зовётся на каждое соединение.
    keying: Keying,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("version", &self.config.version)
            .field("obfs", &self.config.obfs)
            .finish()
    }
}

impl Connector {
    /// Собирает соединитель. Соединения при этом не открывается.
    pub fn new(config: SnellConfig, dialer: Arc<dyn Dialer>) -> SnellResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;
        let keying = crypto::keying(config.psk.clone(), config.version.algorithm());

        Ok(Self {
            config,
            dialer,
            host,
            port,
            keying,
        })
    }

    /// Настройки направления.
    pub fn config(&self) -> &SnellConfig {
        &self.config
    }

    /// Открывает соединение и накладывает обфускацию.
    async fn plain(&self) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let io = connect::dial(&*self.dialer, &self.host, self.port).await?;

        Ok(match self.config.obfs {
            Mode::None => Box::new(io),
            Mode::Http => Box::new(HttpObfs::new(io, self.config.obfs_host(), self.port)),
            Mode::Tls => Box::new(TlsObfs::new(io, self.config.obfs_host())),
        })
    }

    /// Открывает поток и отправляет заголовок.
    ///
    /// Соль и заголовок уходят одной записью — у обоих кадров по-своему, но
    /// с одинаковым намерением: два пакета там, где протокол шлёт один, видны
    /// по дороге.
    pub async fn open(&self, header: &[u8]) -> Result<Opened, ProtocolError> {
        let mut io = self.plain().await?;

        // Соль бросается на каждое соединение: она и есть то, что делает
        // сеансовый ключ разным. Повтор пары «ключ, счётчик» для AEAD
        // означает раскрытые данные, а не «слабее».
        let mut salt = vec![0u8; SALT_LEN];
        rand::thread_rng().fill(&mut salt[..]);
        let mut send = self.keying.cipher(&salt).map_err(SnellError::from)?;

        if self.config.version.framed() {
            let mut stream = V4Stream::new(io, self.keying.clone(), salt, send);
            deadline::handshake::<_, SnellError>("заголовок Snell", async {
                stream.write_all(header).await?;
                stream.flush().await?;
                Ok(())
            })
            .await?;
            return Ok(Opened::Framed(stream));
        }

        let mut first = salt;
        first.extend_from_slice(&seal_chunk(&mut send, header).map_err(SnellError::from)?);

        deadline::handshake::<_, SnellError>("заголовок Snell", async {
            io.write_all(&first).await?;
            io.flush().await?;
            Ok(())
        })
        .await?;

        Ok(Opened::Chunks(ChunkStream::new(
            io,
            self.keying.clone(),
            send,
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use tokio::net::{TcpStream, UdpSocket};

    use super::*;
    use crate::version::Version;

    /// Звонящий, который никуда не звонит.
    #[derive(Debug)]
    struct NoDialer;

    #[async_trait::async_trait]
    impl Dialer for NoDialer {
        async fn dial_tcp(&self, _addr: SocketAddr) -> Result<TcpStream, ProtocolError> {
            Err(ProtocolError::Unsupported("сеть в тесте"))
        }

        async fn bind_udp(&self, _local: SocketAddr) -> Result<UdpSocket, ProtocolError> {
            Err(ProtocolError::Unsupported("сеть в тесте"))
        }

        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
            Err(ProtocolError::Unsupported("сеть в тесте"))
        }
    }

    fn config() -> SnellConfig {
        SnellConfig {
            server: "example.com:8443".to_owned(),
            psk: "secret".to_owned(),
            version: Version::V3,
            ..SnellConfig::default()
        }
    }

    fn connector(config: SnellConfig) -> SnellResult<Connector> {
        Connector::new(config, Arc::new(NoDialer))
    }

    #[test]
    fn bad_settings_are_caught_before_any_connection() {
        assert!(
            connector(SnellConfig {
                psk: String::new(),
                ..config()
            })
            .is_err()
        );
    }

    #[test]
    fn the_key_derivation_follows_the_version() {
        // Первая версия шифрует ChaCha20, остальные — AES-128, и длина ключа
        // у них разная. Ошибка здесь видна только молчанием сервера.
        let first = connector(SnellConfig {
            version: Version::V1,
            ..config()
        })
        .expect("собирается");
        assert_eq!(first.keying.algorithm().key_len(), 32);

        let third = connector(config()).expect("собирается");
        assert_eq!(third.keying.algorithm().key_len(), 16);
    }

    #[test]
    fn the_salt_is_sixteen_bytes_whatever_the_cipher() {
        // В отличие от Shadowsocks, где длина соли равна длине ключа.
        for version in [Version::V1, Version::V3] {
            let connector = connector(SnellConfig {
                version,
                ..config()
            })
            .expect("собирается");
            assert_eq!(connector.keying.salt_len(), SALT_LEN, "{version}");
        }
    }
}
