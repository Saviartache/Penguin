//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory, parse_params};
use penguin_proto::outbound::Outbound;

use crate::config::PingwinConfig;
use crate::outbound::PingwinOutbound;

/// Фабрика сервера Pingwin.
#[derive(Debug, Default, Clone, Copy)]
pub struct PingwinFactory;

impl PingwinFactory {
    /// Новая фабрика.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(&self, params: &serde_json::Value) -> Result<PingwinConfig, ProtocolError> {
        parse_params(self.protocol(), params)
    }
}

#[async_trait]
impl ProtocolFactory for PingwinFactory {
    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
        // Проверка без сети: интерфейс должен показать ошибку в поле сразу,
        // а не через минуту неудачного подключения.
        self.parse(params)?.validate().map_err(Into::into)
    }

    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn Outbound>, ProtocolError> {
        let config = self.parse(params)?;
        let outbound = PingwinOutbound::new(ctx.id, config, ctx.dialer)?;

        // Первая несущая поднимается **здесь**, а не на первом потоке.
        //
        // Ленивый подъём выглядел выгоднее: рукопожатие уезжало вместе с
        // первым запросом, и подключение стоило ноль. Стоило оно другого —
        // правды. Движок считает направление поднятым, как только `build`
        // вернул его, включает TUN и пишет «подключено»; сходить к серверу до
        // этого было некому. Человек с провайдером, который режет путь до
        // сервера, видел «подключено», задержку «—» и ноль соединений — и
        // искал поломку у себя.
        //
        // Оборот, который здесь платится, — это ровно то, что слово
        // «подключиться» и означает. Экономия 0-RTT при этом никуда не
        // делась: она на **потоках**, а их за время тоннеля тысячи.
        outbound.warm_up().await?;
        Ok(Arc::new(outbound))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn params() -> serde_json::Value {
        json!({
            "server": "example.com:443",
            "key": penguin_core::base64::encode(&[7u8; 32]),
            "password": "secret",
        })
    }

    #[test]
    fn validates_a_good_config() {
        PingwinFactory::new()
            .validate(&params())
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_config_without_a_server_key() {
        // Ключ сервера — не украшение: на нём стоит и опознание сервера, и
        // устойчивость к активной проверке.
        let mut params = params();
        params["key"] = json!("");
        assert!(PingwinFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_missing_address() {
        assert!(PingwinFactory::new().validate(&json!({})).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let mut params = params();
        params["passwort"] = json!("y");
        assert!(PingwinFactory::new().validate(&params).is_err());
    }

    #[test]
    fn the_protocol_name_is_stable() {
        // Имя стоит в конфигурациях пользователей — менять его нельзя.
        assert_eq!(PingwinFactory::new().protocol(), "pingwin");
    }
}
