//! Регистрация протокола: разбор конфигурации, вход, поднятие тоннеля.
//!
//! В отличие от потоковых протоколов, [`PacketFactory::build`] не может
//! отложить рукопожатие до первого потока — потоков здесь нет вовсе, а
//! адрес интерфейса и MTU, которые обязана вернуть [`interface`], сервер
//! называет только при входе. Поэтому весь обмен — HTTPS/XML и `CONNECT` —
//! происходит прямо здесь, и `build` возвращает либо работающий тоннель, либо
//! ошибку, объясняющую, на каком шаге он не поднялся.
//!
//! [`interface`]: penguin_proto::packet::PacketOutbound::interface

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, parse_params};
use penguin_proto::packet::{PacketFactory, PacketOutbound};
use penguin_transport::tls::{ALPN_HTTP11, TlsClient};

use crate::PROTOCOL;
use crate::auth;
use crate::config::OpenConnectConfig;
use crate::cstp::{self, CstpConnection};

/// Фабрика OpenConnect.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenConnectFactory;

impl OpenConnectFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<OpenConnectConfig, ProtocolError> {
        parse_params("OpenConnect", params)
    }
}

#[async_trait]
impl PacketFactory for OpenConnectFactory {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
        // Без сети: интерфейс обязан показать ошибку в поле сразу, а не через
        // минуту неудачного входа.
        Self::parse(params)?.validate().map_err(ProtocolError::from)
    }

    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn PacketOutbound>, ProtocolError> {
        let config = Self::parse(params)?;
        config.validate().map_err(ProtocolError::from)?;

        let (host, port) = config.endpoint().map_err(ProtocolError::from)?;
        let host_header = config.host().map_err(ProtocolError::from)?;
        let tls =
            TlsClient::new(&config.tls, &host, &[ALPN_HTTP11]).map_err(ProtocolError::from)?;

        // Шаг первый: HTTPS + XML, до `id="success"` или явного отказа.
        let login = auth::login(&*ctx.dialer, &tls, &host, port, &host_header, &config)
            .await
            .map_err(ProtocolError::from)?;

        // Шаг второй: отдельное TLS-соединение, `CONNECT`, адрес и сроки от
        // сервера (см. документ `auth` и `cstp::connect`).
        let (io, tail, tunnel) =
            cstp::connect::open(&*ctx.dialer, &tls, &host, port, &host_header, &login.cookie)
                .await
                .map_err(ProtocolError::from)?;

        let connection = CstpConnection::new(ctx.id, io, tail, tunnel);
        Ok(Arc::new(connection))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_a_good_config() {
        let params = json!({
            "server": "vpn.example.com:443",
            "username": "ivan",
            "password": "secret"
        });
        OpenConnectFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_username() {
        let params = json!({ "server": "vpn.example.com:443", "password": "secret" });
        assert!(OpenConnectFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_missing_password() {
        let params = json!({ "server": "vpn.example.com:443", "username": "ivan" });
        assert!(OpenConnectFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_address_without_recognisable_shape() {
        let params = json!({ "server": "", "username": "ivan", "password": "secret" });
        assert!(OpenConnectFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let params = json!({
            "server": "vpn.example.com:443",
            "username": "ivan",
            "password": "secret",
            "otp": "123456"
        });
        assert!(OpenConnectFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        // Имя стоит в конфигурациях пользователей — менять его нельзя.
        assert_eq!(OpenConnectFactory::new().protocol(), "openconnect");
    }
}
