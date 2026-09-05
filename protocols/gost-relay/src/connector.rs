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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::config::{GostRelayConfig, Security, Transport};
use crate::error::{GostRelayError, GostRelayResult};
use crate::frame::{request, response};

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
            read_response(&mut io, target).await
        })
        .await?;

        Ok(io)
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

/// Читает заголовок ответа и превращает статус, отличный от успеха, в
/// ошибку.
///
/// Признаки ответа дочитываются и отбрасываются, даже когда сервер по факту
/// ничего в них не кладёт (см. документ [`response`]): иначе один сервер,
/// который однажды решит что-то туда положить, испортит начало потока
/// приложения.
async fn read_response<S>(io: &mut S, target: &SocketAddress) -> GostRelayResult<()>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0u8; 4];
    io.read_exact(&mut head).await?;
    let head = response::parse_header(head);

    if head.version != request::VERSION {
        return Err(GostRelayError::malformed(format!(
            "версия ответа {:#04x} вместо {:#04x}",
            head.version,
            request::VERSION
        )));
    }

    if head.feature_len > 0 {
        let mut discard = vec![0u8; usize::from(head.feature_len)];
        io.read_exact(&mut discard).await?;
    }

    match head.status {
        response::STATUS_OK => Ok(()),
        response::STATUS_UNAUTHORIZED => Err(GostRelayError::AuthRejected),
        status => Err(GostRelayError::Refused {
            target: target.to_string(),
            reason: response::status_text(status),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SocketAddress {
        SocketAddress::domain("example.com", 443)
    }

    #[tokio::test]
    async fn a_successful_response_drains_its_features() {
        let mut wire = vec![request::VERSION, response::STATUS_OK, 0x00, 0x03];
        wire.extend_from_slice(b"xyz");
        wire.extend_from_slice("дальше идут данные приложения".as_bytes());

        let mut io = std::io::Cursor::new(wire);
        read_response(&mut io, &target()).await.expect("успех");

        let mut rest = Vec::new();
        io.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, "дальше идут данные приложения".as_bytes());
    }

    #[tokio::test]
    async fn unauthorized_becomes_auth_rejected() {
        let wire = [request::VERSION, response::STATUS_UNAUTHORIZED, 0x00, 0x00];
        let mut io = std::io::Cursor::new(wire);
        let err = read_response(&mut io, &target()).await.expect_err("отказ");
        assert!(matches!(err, GostRelayError::AuthRejected));
    }

    #[tokio::test]
    async fn other_statuses_become_a_named_refusal() {
        let wire = [
            request::VERSION,
            response::STATUS_HOST_UNREACHABLE,
            0x00,
            0x00,
        ];
        let mut io = std::io::Cursor::new(wire);
        let err = read_response(&mut io, &target()).await.expect_err("отказ");
        match err {
            GostRelayError::Refused { target, reason } => {
                assert_eq!(target, "example.com:443");
                assert_eq!(
                    reason,
                    response::status_text(response::STATUS_HOST_UNREACHABLE)
                );
            }
            other => panic!("не тот вариант: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_wrong_version_is_not_a_status_to_interpret() {
        // Чужой протокол на этом порту тоже может прислать что-то похожее
        // на успех — версия обязана быть проверена раньше статуса.
        let wire = [0x05, response::STATUS_OK, 0x00, 0x00];
        let mut io = std::io::Cursor::new(wire);
        let err = read_response(&mut io, &target()).await.expect_err("не то");
        assert!(matches!(err, GostRelayError::Malformed(_)));
    }
}
