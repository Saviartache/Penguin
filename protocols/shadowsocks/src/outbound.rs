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
use tokio::io::AsyncWriteExt;

use crate::config::ShadowsocksConfig;
use crate::crypto::{Cipher, Method, kdf};
use crate::datagram::ShadowsocksDatagram;
use crate::error::{ShadowsocksError, ShadowsocksResult};
use crate::stream::{SsStream, seal_chunk};

/// Исходящее направление через сервер Shadowsocks.
pub struct ShadowsocksOutbound {
    id: OutboundId,
    config: ShadowsocksConfig,
    /// Хост сервера, разобранный один раз при сборке.
    host: Address,
    /// Порт сервера.
    port: u16,
    /// Главный ключ: выводится из пароля один раз, а не на каждый поток.
    master: Vec<u8>,
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
        let master = kdf::master_key(&config.password, config.method);

        Ok(Self {
            id,
            config,
            host,
            port,
            master,
            dialer,
        })
    }

    /// Метод шифрования.
    fn method(&self) -> Method {
        self.config.method
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
        let method = self.method();
        let mut io = connect::dial(&*self.dialer, &self.host, self.port).await?;

        // Соль бросается на каждое соединение: она и есть то, что делает
        // сеансовый ключ разным. Повтор пары «ключ, счётчик» для AEAD
        // означает раскрытые данные, а не «слабее».
        let mut salt = vec![0u8; method.salt_len()];
        rand::thread_rng().fill(&mut salt[..]);

        let key = kdf::session_key(&self.master, &salt, method).map_err(ProtocolError::from)?;
        let mut send = Cipher::new(method, &key).map_err(ProtocolError::from)?;

        // Адрес назначения — первый кусок внутри шифра. Он и соль уходят
        // одной записью: два пакета там, где протокол шлёт один, видны по
        // дороге.
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

        Ok(Box::new(SsStream::new(
            io,
            method,
            self.master.clone(),
            send,
        )))
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
        Ok(Box::new(ShadowsocksDatagram::new(
            socket,
            server,
            self.method(),
            self.master.clone(),
        )))
    }
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
