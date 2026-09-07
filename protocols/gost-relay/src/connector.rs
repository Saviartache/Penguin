//! Как открыть поток до сервера: сокет, TLS, перенос, заголовок GOST Relay.
//!
//! Отдельно от [`crate::outbound`], потому что зовут это двое: сам выход и
//! канал датаграмм. У GOST Relay в режиме UDP адрес назначения назван в
//! заголовке потока, то есть на каждого адресата нужен свой поток со своим
//! заголовком, — и открывать их умеет канал ([`crate::datagram`]), а не
//! только направление.

use std::sync::Arc;

use penguin_core::address::{Address, SocketAddress};
use penguin_proto::connect;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;
use penguin_transport::tls::TlsClient;
use penguin_transport::{deadline, httpupgrade, ws};
use tokio::io::AsyncWriteExt;

use crate::config::{GostRelayConfig, Security, Transport};
use crate::error::{GostRelayError, GostRelayResult};
use crate::frame::request;
use crate::stream::GostRelayStream;

/// Всё, что нужно, чтобы открыть поток до сервера.
pub struct Connector {
    /// Хост сервера, разобранный один раз при сборке.
    host: Address,
    /// Порт сервера.
    port: u16,
    username: String,
    password: String,
    /// Собранный слой TLS. `None` — `security = "none"`.
    tls: Option<TlsClient>,
    transport: Transport,
    /// Путь запроса для переносов поверх HTTP.
    path: String,
    /// Заголовок `Host` для них же.
    http_host: String,
    dialer: Arc<dyn Dialer>,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls.is_some())
            .field("transport", &self.transport)
            .finish()
    }
}

impl Connector {
    /// Собирает соединитель по проверенным настройкам.
    pub fn new(config: &GostRelayConfig, dialer: Arc<dyn Dialer>) -> GostRelayResult<Self> {
        let (host, port) = config.endpoint()?;
        let tls = match config.security {
            Security::Tls => Some(TlsClient::new(
                &config.tls,
                &host,
                config.transport.default_alpn(),
            )?),
            Security::None => None,
        };

        Ok(Self {
            host,
            port,
            username: config.username.clone(),
            password: config.password.clone(),
            tls,
            transport: config.transport,
            path: config.path().to_owned(),
            http_host: config.host()?,
            dialer,
        })
    }

    /// Имя и пароль для признака `FeatureUserAuth`.
    ///
    /// `None`, если ни одно поле не заполнено: эталонный клиент в этом
    /// случае признак вообще не посылает, и сервер без настроенных
    /// пользователей опознание не спрашивает.
    fn auth(&self) -> Option<(&str, &str)> {
        if self.username.is_empty() && self.password.is_empty() {
            None
        } else {
            Some((&self.username, &self.password))
        }
    }

    /// Открывает поток TCP до `target` через `CmdConnect`.
    pub async fn open_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        self.open(request::CMD_CONNECT, false, target).await
    }

    /// Открывает поток-туннель UDP до одного адресата.
    ///
    /// GOST Relay умеет настоящий `UDP ASSOCIATE` (`CmdBind` с флагом UDP),
    /// но сервер включает его отдельной настройкой, выключенной по
    /// умолчанию (документ [`crate::datagram`]). Здесь — режим, который
    /// работает без неё: `CmdConnect` с флагом UDP привязывает поток к
    /// одному адресату так же, как обычное TCP-соединение.
    pub async fn open_udp_tunnel(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        self.open(request::CMD_CONNECT | request::FLAG_UDP, true, target)
            .await
    }

    /// Общая часть: перенос, заголовок, ответ.
    async fn open(
        &self,
        cmd: u8,
        udp: bool,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let mut io = self.carry().await?;
        let header = request::build(cmd, udp, self.auth(), target)?;

        deadline::handshake::<_, GostRelayError>("заголовок GOST Relay", async {
            io.write_all(&header).await?;
            io.flush().await?;
            Ok(())
        })
        .await?;

        // Ответ не вычитывается здесь: сервер придерживает его до первых
        // данных от адресата, а их не будет, пока не уйдёт запрос
        // приложения. Заголовок снимает поток, при первом чтении
        // ([`crate::stream`]).
        Ok(Box::new(GostRelayStream::new(io, target.to_string())))
    }

    /// Соединение до сервера вместе с переносом, но без заголовка запроса.
    async fn carry(&self) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let plain = connect::dial(&*self.dialer, &self.host, self.port).await?;

        let secure: Box<dyn ProxyStream> = match &self.tls {
            Some(tls) => Box::new(tls.connect(plain).await.map_err(GostRelayError::from)?),
            None => Box::new(plain),
        };

        Ok(match self.transport {
            Transport::Tcp => secure,
            Transport::Ws => {
                let request = ws::Request::new(self.http_host.clone(), self.path.clone());
                Box::new(
                    ws::connect(secure, &request)
                        .await
                        .map_err(GostRelayError::from)?,
                )
            }
            Transport::Httpupgrade => {
                let request = ws::Request::new(self.http_host.clone(), self.path.clone());
                let upgraded = httpupgrade::connect(secure, &request)
                    .await
                    .map_err(GostRelayError::from)?;
                // Заголовок запроса мы ещё не отправили, и отвечать серверу
                // нечем: данные до него означают, что на том конце не GOST
                // Relay.
                if !upgraded.tail.is_empty() {
                    return Err(GostRelayError::malformed(
                        "сервер прислал данные до нашего заголовка",
                    )
                    .into());
                }
                Box::new(upgraded.io)
            }
        })
    }

    /// Проверяет, что сервер на месте и (если TLS включён) предъявляет
    /// ожидаемый сертификат.
    ///
    /// Заголовок `CmdConnect` при этом не уходит: ему нужен настоящий адрес
    /// назначения, а на этом шаге его ещё нет. Значит, ни имя, ни пароль
    /// здесь не проверяются — как и у VLESS, это выясняется только на
    /// первом настоящем соединении.
    pub async fn verify(&self) -> Result<(), ProtocolError> {
        let _carrier = self.carry().await?;
        Ok(())
    }
}

