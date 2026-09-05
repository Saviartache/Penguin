//! Как открывается TCP-соединение до сервера.
//!
//! У Mieru нет TLS: то, что у AnyTLS или Trojan делает рукопожатие
//! сертификата, здесь просто не существует — всё шифрование живёт в самих
//! сегментах (`cipher`, `segment`). Соединитель поэтому только открывает
//! сокет; опознание случается позже, самим фактом, что сервер сумел
//! расшифровать первый сегмент.

use std::sync::Arc;

use penguin_core::address::Address;
use penguin_proto::connect;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;

use crate::config::MieruConfig;
use crate::error::MieruResult;

/// Как открывать TCP-соединения до сервера Mieru.
pub struct Connector {
    host: Address,
    port: u16,
    dialer: Arc<dyn Dialer>,
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
    pub fn new(config: &MieruConfig, dialer: Arc<dyn Dialer>) -> MieruResult<Self> {
        let (host, port) = config.endpoint()?;
        Ok(Self { host, port, dialer })
    }

    /// Открывает новое TCP-соединение — будущее «неявное соединение»
    /// (underlay), поверх которого поднимется одна или несколько сессий.
    pub async fn connect(&self) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let plain = connect::dial(&*self.dialer, &self.host, self.port).await?;
        Ok(Box::new(plain))
    }
}
