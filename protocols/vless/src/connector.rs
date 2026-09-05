//! Как открыть поток до сервера: сокет, TLS, перенос, заголовок.
//!
//! Отдельно от [`crate::outbound`], потому что зовут это двое: сам выход и
//! канал датаграмм. У VLESS адрес назначения назван в заголовке, то есть на
//! каждого адресата нужен свой поток со своим заголовком, — и открывать их
//! умеет канал, а не только направление.
//!
//! Держать ради этого ссылку на направление значило бы завести цикл; вместо
//! него оба держат один [`Connector`].

use std::sync::Arc;

use penguin_core::address::{Address, SocketAddress};
use penguin_core::uuid::Uuid;
use penguin_proto::connect;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;
use penguin_transport::tls::TlsClient;
use penguin_transport::{deadline, httpupgrade, ws};
use tokio::io::AsyncWriteExt;

use crate::config::{Security, Transport, VlessConfig};
use crate::error::{VlessError, VlessResult};
use crate::frame::request;
use crate::reality::{self, RealityConfig};
use crate::stream::VlessStream;

/// Всё, что нужно, чтобы открыть поток до сервера.
pub struct Connector {
    /// Хост сервера, разобранный один раз при сборке.
    host: Address,
    /// Порт сервера.
    port: u16,
    uuid: Uuid,
    /// Собранный слой TLS. `None` — `security` не `"tls"`.
    tls: Option<TlsClient>,
    /// Настройки Reality. `None` — `security` не `"reality"`.
    reality: Option<RealityConfig>,
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
            .field("reality", &self.reality.is_some())
            .field("transport", &self.transport)
            .finish()
    }
}

impl Connector {
    /// Собирает соединитель по проверенным настройкам.
    pub fn new(config: &VlessConfig, dialer: Arc<dyn Dialer>) -> VlessResult<Self> {
        let (host, port) = config.endpoint()?;
        let (tls, reality) = match config.security {
            Security::Tls => (
                Some(TlsClient::new(
                    &config.tls,
                    &host,
                    config.transport.default_alpn(),
                )?),
                None,
            ),
            Security::None => (None, None),
            Security::Reality => {
                // `config.validate()` (позвана раньше, в `VlessOutbound::new`)
                // уже отказала бы на отсутствующем блоке — здесь всё равно
                // не `unwrap`, а явная ошибка: разбор конфигурации и подъём
                // направления не обязаны быть одним и тем же вызовом.
                let reality = config.reality.clone().ok_or_else(|| {
                    VlessError::config("`security = \"reality\"` без блока `reality`")
                })?;
                (None, Some(reality))
            }
        };

        Ok(Self {
            host,
            port,
            uuid: config.uuid,
            tls,
            reality,
            transport: config.transport,
            path: config.path().to_owned(),
            http_host: config.host()?,
            dialer: Arc::clone(&dialer),
        })
    }

    /// Открывает поток и отправляет заголовок запроса.
    pub async fn open(
        &self,
        command: u8,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        if self.reality.is_some() {
            // См. `crate::reality`: рукопожатие доходит до сертификата
            // сервера и проверяет его, но не продолжается до Finished и
            // прикладных ключей TLS 1.3 — поток, о котором эта проверка
            // ничего не знает, не готов нести байты VLESS. Отказ здесь —
            // не временная затычка, а честный ответ на вопрос «а что
            // случится, если я всё-таки попробую подключиться»: тихо
            // притвориться работающим каналом хуже, чем отказать.
            return Err(VlessError::config(
                "VLESS поверх Reality пока проверяет сервер, но не соединяет: рукопожатие \
                 останавливается на сертификате и не продолжается до прикладных ключей TLS 1.3 \
                 (см. penguin_vless::reality)",
            )
            .into());
        }

        let mut io = self.carry().await?;
        let header = request::request(&self.uuid, command, target)?;

        deadline::handshake::<_, VlessError>("заголовок VLESS", async {
            io.write_all(&header).await?;
            io.flush().await?;
            Ok(())
        })
        .await?;

        Ok(Box::new(VlessStream::new(io)))
    }

    /// Соединение до сервера вместе с переносом, но без заголовка.
    async fn carry(&self) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let plain = connect::dial(&*self.dialer, &self.host, self.port).await?;

        let secure: Box<dyn ProxyStream> = match &self.tls {
            Some(tls) => Box::new(tls.connect(plain).await.map_err(VlessError::from)?),
            None => Box::new(plain),
        };

        Ok(match self.transport {
            Transport::Tcp => secure,
            Transport::Ws => {
                let request = ws::Request::new(self.http_host.clone(), self.path.clone());
                Box::new(
                    ws::connect(secure, &request)
                        .await
                        .map_err(VlessError::from)?,
                )
            }
            Transport::Httpupgrade => {
                let request = ws::Request::new(self.http_host.clone(), self.path.clone());
                let upgraded = httpupgrade::connect(secure, &request)
                    .await
                    .map_err(VlessError::from)?;
                // Заголовок запроса мы ещё не отправили, и отвечать серверу
                // нечем: данные до него означают, что на том конце не VLESS.
                if !upgraded.tail.is_empty() {
                    return Err(
                        VlessError::malformed("сервер прислал данные до нашего заголовка").into(),
                    );
                }
                Box::new(upgraded.io)
            }
        })
    }

    /// Проверяет, что сервер на месте и предъявляет ожидаемый сертификат
    /// (`security = "tls"`/`"none"`) либо подтверждает себя как Reality
    /// (`security = "reality"`).
    ///
    /// UUID здесь не проверяется, и проверить его нечем: сервер, не узнавший
    /// его, закрывает соединение молча — как и Trojan. Заголовок при этом не
    /// отправляется: соединение до чужого адреса, о котором никто не просил,
    /// в журнале сервера выглядит чужим трафиком.
    ///
    /// У Reality эта проверка — единственное, что вообще можно сделать с
    /// сервером сейчас (см. [`Self::open`]): она честная и самостоятельная
    /// (доходит до HMAC-подтверждения сертификата, а не только до открытия
    /// сокета), но не открывает канал для данных.
    pub async fn verify(&self) -> Result<(), ProtocolError> {
        if let Some(config) = &self.reality {
            let mut plain = connect::dial(&*self.dialer, &self.host, self.port).await?;
            deadline::handshake::<_, VlessError>("рукопожатие Reality", async {
                reality::verify(&mut plain, config).await?;
                Ok(())
            })
            .await?;
            return Ok(());
        }

        let _carrier = self.carry().await?;
        Ok(())
    }
}
