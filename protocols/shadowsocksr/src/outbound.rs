//! Направление через сервер ShadowsocksR.
//!
//! Главный ключ выводится из пароля один раз при постройке — это дорого
//! считать заново на каждый поток. `client_id`/`connection_id` для `auth_*`
//! (см. `crate::protocol::client_id`) тоже общие на весь выход по той же
//! причине, что и у эталона: сервер помнит недавние `client_id` и отвергнет
//! выход, который на каждое соединение представляется заново.

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

use crate::config::ShadowsocksrConfig;
use crate::crypto::cipher;
use crate::crypto::kdf;
use crate::error::{ShadowsocksrError, ShadowsocksrResult};
use crate::obfs::state::ObfsState;
use crate::protocol::client_id::ClientIdState;
use crate::protocol::state::ProtocolState;
use crate::stream::SsrStream;

/// Исходящее направление через сервер ShadowsocksR.
pub struct ShadowsocksrOutbound {
    id: OutboundId,
    config: ShadowsocksrConfig,
    /// Хост сервера, разобранный один раз при сборке.
    host: Address,
    /// Порт сервера.
    port: u16,
    /// Главный ключ: выводится из пароля один раз, а не на каждый поток.
    master_key: Vec<u8>,
    /// Общий на весь выход счётчик соединений для `auth_aes128_*`.
    client_id: Arc<ClientIdState>,
    dialer: Arc<dyn Dialer>,
}

impl std::fmt::Debug for ShadowsocksrOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksrOutbound")
            .field("id", &self.id)
            .field("config", &self.config)
            .finish()
    }
}

impl ShadowsocksrOutbound {
    /// Собирает направление. Соединения при этом не открывается.
    pub fn new(
        id: OutboundId,
        config: ShadowsocksrConfig,
        dialer: Arc<dyn Dialer>,
    ) -> ShadowsocksrResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;
        let master_key = kdf::evp_bytes_to_key(config.password.as_bytes(), config.method.key_len());

        Ok(Self {
            id,
            config,
            host,
            port,
            master_key,
            client_id: Arc::new(ClientIdState::new()),
            dialer,
        })
    }
}

#[async_trait]
impl Outbound for ShadowsocksrOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // UDP у ShadowsocksR не реализован в этой версии крейта — см.
            // документ крейта. Заявить `true` здесь означало бы, что
            // DNS-запросы уйдут в направление, которое сразу же откажет.
            udp: false,
            // Своя соль (IV) и свой сеансовый ключ на каждый поток.
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
        let method = self.config.method;
        let mut io = connect::dial(&*self.dialer, &self.host, self.port).await?;

        // IV на запись — случайные байты, свои на каждое соединение (см.
        // документ `crypto::kdf`). Повтор пары «ключ, IV» — это раскрытые
        // данные для CTR и предсказуемый ключевой поток для CFB.
        let mut write_iv = vec![0u8; method.iv_len()];
        rand::thread_rng().fill(&mut write_iv[..]);
        let mut write_cipher = cipher::build_encryptor(method, &self.master_key, &write_iv)?;

        // Адрес назначения — первый кусок открытого текста, ещё до всякого
        // кадрирования и шифра.
        let mut address = Vec::new();
        socks::encode(target, &mut address).map_err(ShadowsocksrError::from)?;
        let head_size = method.iv_len() + address.len();

        let mut protocol_state = ProtocolState::new(
            self.config.protocol_method,
            self.master_key.clone(),
            write_iv.clone(),
        );
        let header = protocol_state
            .needs_auth_header()
            .then(|| self.client_id.next());

        let mut obfs_state = ObfsState::new(
            self.config.obfs,
            self.host.to_string(),
            self.port,
            self.config.obfs_param.clone(),
            head_size,
        );

        let mut framed = protocol_state.client_pre_encrypt(&address, head_size, header)?;
        write_cipher.apply(&mut framed);
        let mut first = write_iv;
        first.extend_from_slice(&framed);
        let encoded = obfs_state.client_encode(&first);

        deadline::handshake::<_, ShadowsocksrError>(
            "адрес назначения ShadowsocksR",
            async {
                io.write_all(&encoded).await?;
                io.flush().await?;
                Ok(())
            },
        )
        .await?;

        Ok(Box::new(SsrStream::new(
            io,
            method,
            self.master_key.clone(),
            obfs_state,
            protocol_state,
            write_cipher,
        )))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        Err(ShadowsocksrError::UdpUnimplemented.into())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use super::*;

    #[test]
    fn the_debug_output_hides_the_password() {
        // Само направление тестами на живом сокете не проверяется — это
        // `scripts/interop`, а не юнит-тест. Здесь только то, что можно
        // проверить без сети: пароль не должен всплыть в `Debug`.
        let config = ShadowsocksrConfig {
            server: "example.com:8388".to_owned(),
            method: crate::crypto::Method::Aes256Cfb,
            password: "very secret".to_owned(),
            obfs: crate::obfs::ObfsMethod::Plain,
            obfs_param: None,
            protocol_method: crate::protocol::ProtocolMethod::Origin,
        };
        let outbound =
            ShadowsocksrOutbound::new(OutboundId::from("test"), config, Arc::new(NeverDialer))
                .expect("настройки верны");
        let shown = format!("{outbound:?}");
        assert!(!shown.contains("very secret"), "{shown}");
    }

    struct NeverDialer;

    #[async_trait]
    impl Dialer for NeverDialer {
        async fn dial_tcp(
            &self,
            _addr: SocketAddr,
        ) -> Result<tokio::net::TcpStream, ProtocolError> {
            Err(ProtocolError::Connect("тест не открывает сокетов".into()))
        }

        async fn bind_udp(
            &self,
            _local: SocketAddr,
        ) -> Result<tokio::net::UdpSocket, ProtocolError> {
            Err(ProtocolError::Connect("тест не открывает сокетов".into()))
        }

        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
            Ok(Vec::new())
        }
    }
}
