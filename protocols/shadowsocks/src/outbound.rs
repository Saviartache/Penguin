//! Направление через сервер Shadowsocks.
//!
//! Состояния между вызовами не держит: у каждого потока своя соль и свой
//! сеансовый ключ. Собрано заранее ровно то, что дорого считать заново, —
//! главный ключ из пароля.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::address::{Address, SocketAddress};
use penguin_core::id::OutboundId;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::connect;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use penguin_transport::addr::socks;
use penguin_transport::deadline;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::config::ShadowsocksConfig;
use crate::crypto::{Cipher, Method, kdf};
use crate::datagram::ShadowsocksDatagram;
use crate::error::{ShadowsocksError, ShadowsocksResult};
use crate::header2022;
use crate::kdf2022;
use crate::method::{Method2022, ShadowsocksMethod};
use crate::stream::{self, seal_chunk};
use crate::tcp2022;
use crate::udp2022::ShadowsocksDatagram2022;

/// Исходящее направление через сервер Shadowsocks.
pub struct ShadowsocksOutbound {
    id: OutboundId,
    config: ShadowsocksConfig,
    /// Хост сервера, разобранный один раз при сборке.
    host: Address,
    /// Порт сервера.
    port: u16,
    /// Ключевой материал направления: главный ключ AEAD (из пароля) или PSK
    /// 2022 (из base64) — оба лежат здесь одинаково, различает их только
    /// метод. Готовится один раз при сборке, а не на каждый поток.
    key: Vec<u8>,
    dialer: Arc<dyn Dialer>,
}

impl std::fmt::Debug for ShadowsocksOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksOutbound")
            .field("id", &self.id)
            .field("config", &self.config)
            .finish()
    }
}

impl ShadowsocksOutbound {
    /// Собирает направление.
    ///
    /// Соединения при этом не открывается: у Shadowsocks его и не бывает
    /// постоянного.
    pub fn new(
        id: OutboundId,
        config: ShadowsocksConfig,
        dialer: Arc<dyn Dialer>,
    ) -> ShadowsocksResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;

        // `validate` уже проверила и то, и другое: здесь остаётся получить
        // байты, а не решить, годятся ли они.
        let key = match config.method {
            ShadowsocksMethod::Aead(method) => kdf::master_key(&config.password, method),
            ShadowsocksMethod::Aead2022(method) => penguin_core::base64::decode_exact(
                &config.password,
                method.key_len(),
                "ключ Shadowsocks 2022",
            )
            .map_err(|e| ShadowsocksError::config(e.to_string()))?,
        };

        Ok(Self {
            id,
            config,
            host,
            port,
            key,
            dialer,
        })
    }
}

#[async_trait]
impl Outbound for ShadowsocksOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // Ровно то, что стоит в настройках: соврать здесь означает, что
            // DNS-запросы уйдут в направление, которое их молча потеряет.
            udp: self.config.udp,
            // Своя соль и свой ключ на каждый поток.
            multiplex: false,
            port_hopping: false,
            // Имя уезжает серверу доменом и разрешается на той стороне.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let io = connect::dial(&*self.dialer, &self.host, self.port).await?;

        match self.config.method {
            ShadowsocksMethod::Aead(method) => {
                connect_tcp_aead(io, method, &self.key, target).await
            }
            ShadowsocksMethod::Aead2022(method) => {
                connect_tcp_2022(io, method, &self.key, target).await
            }
        }
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        if !self.config.udp {
            return Err(ShadowsocksError::UdpDisabled.into());
        }

        // Адрес сервера нужен числовым: датаграммы шлются сокетом, а он имён
        // не знает. Разрешает имя `Dialer` — мимо тоннеля, как и всё
        // остальное.
        let server = first_address(&*self.dialer, &self.host, self.port).await?;
        let local = SocketAddr::new(
            if server.is_ipv6() {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            },
            0,
        );

        let socket = self.dialer.bind_udp(local).await?;
        match self.config.method {
            ShadowsocksMethod::Aead(method) => Ok(Box::new(ShadowsocksDatagram::new(
                socket,
                server,
                method,
                self.key.clone(),
            ))),
            ShadowsocksMethod::Aead2022(method) => Ok(Box::new(ShadowsocksDatagram2022::new(
                socket,
                server,
                method,
                self.key.clone(),
            ))),
        }
    }
}

/// TCP поверх обычного AEAD: соль, адрес назначения одним куском.
async fn connect_tcp_aead<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    mut io: S,
    method: Method,
    master: &[u8],
    target: &SocketAddress,
) -> Result<Box<dyn ProxyStream>, ProtocolError> {
    // Соль бросается на каждое соединение: она и есть то, что делает
    // сеансовый ключ разным. Повтор пары «ключ, счётчик» для AEAD означает
    // раскрытые данные, а не «слабее».
    let mut salt = vec![0u8; method.salt_len()];
    rand::thread_rng().fill(&mut salt[..]);

    let key = kdf::session_key(master, &salt, method).map_err(ProtocolError::from)?;
    let mut send = Cipher::new(method.algorithm(), &key).map_err(ProtocolError::from)?;

    // Адрес назначения — первый кусок внутри шифра. Он и соль уходят одной
    // записью: два пакета там, где протокол шлёт один, видны по дороге.
    let mut header = Vec::new();
    socks::encode(target, &mut header).map_err(ShadowsocksError::from)?;
    let mut first = salt;
    first.extend_from_slice(&seal_chunk(&mut send, &header).map_err(ProtocolError::from)?);

    deadline::handshake::<_, ShadowsocksError>("адрес назначения Shadowsocks", async {
        io.write_all(&first).await?;
        io.flush().await?;
        Ok(())
    })
    .await?;

    Ok(Box::new(stream::wrap(
        io,
        kdf::keying(master.to_vec(), method),
        send,
    )))
}

/// TCP поверх Shadowsocks 2022: заголовок с меткой времени двумя кусками
/// AEAD, дальше — ответ сервера читает уже [`tcp2022::Ss2022Stream`].
async fn connect_tcp_2022<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    mut io: S,
    method: Method2022,
    psk: &[u8],
    target: &SocketAddress,
) -> Result<Box<dyn ProxyStream>, ProtocolError> {
    let algorithm = method.algorithm();
    let salt_len = method.salt_len();

    let mut salt = vec![0u8; salt_len];
    rand::thread_rng().fill(&mut salt[..]);

    let session_key = kdf2022::derive(psk, &salt, algorithm.key_len());
    let mut send = Cipher::new(algorithm, &session_key).map_err(ProtocolError::from)?;

    let now = header2022::now_unix();
    let (fixed, variable) = tcp2022::header::build_request(target, now)?;

    let mut first = salt.clone();
    first.extend_from_slice(&send.seal(&fixed).map_err(ShadowsocksError::from)?);
    first.extend_from_slice(&send.seal(&variable).map_err(ShadowsocksError::from)?);

    deadline::handshake::<_, ShadowsocksError>("заголовок Shadowsocks 2022", async {
        io.write_all(&first).await?;
        io.flush().await?;
        Ok(())
    })
    .await?;

    Ok(Box::new(tcp2022::Ss2022Stream::new(
        io,
        algorithm,
        psk.to_vec(),
        salt_len,
        salt,
        send,
    )))
}

/// Первый адрес сервера, какой удалось получить.
///
/// Перебирать их, как это делает [`connect::dial`], здесь нечем: у UDP нет
/// «не удалось подключиться», по которому можно было бы понять, что адрес не
/// тот. Берётся первый — тот же, к которому подключился бы TCP.
async fn first_address(
    dialer: &dyn Dialer,
    host: &Address,
    port: u16,
) -> Result<SocketAddr, ProtocolError> {
    let addresses = connect::resolve(dialer, host, port).await?;
    addresses.into_iter().next().ok_or_else(|| {
        ProtocolError::Connect(format!("до `{host}:{port}` не нашлось ни одного адреса"))
    })
}
