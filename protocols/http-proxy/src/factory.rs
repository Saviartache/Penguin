//! Регистрация протокола: разбор конфигурации и сборка направления.
//!
//! Фабрик две, а крейт один: `http` и `https` отличаются одной строкой
//! настройки и ничем больше. Заводить ради этого второй крейт значило бы
//! копировать разбор `CONNECT` — а копия расходится с оригиналом при первой
//! же правке.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::config::HttpProxyConfig;
use crate::outbound::HttpProxyOutbound;
use crate::{PROTOCOL_HTTP, PROTOCOL_HTTPS};

/// Фабрика прокси HTTP CONNECT.
#[derive(Debug, Clone, Copy)]
pub struct HttpProxyFactory {
    /// Обёрнут ли разговор с прокси в TLS.
    secure: bool,
}

impl HttpProxyFactory {
    /// Прокси без TLS: протокол `http`.
    pub fn http() -> Self {
        Self { secure: false }
    }

    /// Прокси под TLS: протокол `https`.
    pub fn https() -> Self {
        Self { secure: true }
    }

    /// Разбирает параметры из конфигурации.
    fn parse(&self, params: &serde_json::Value) -> Result<HttpProxyConfig, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("{}: {e}", self.protocol())))
    }
}

#[async_trait]
impl ProtocolFactory for HttpProxyFactory {
    fn protocol(&self) -> &'static str {
        if self.secure {
            PROTOCOL_HTTPS
        } else {
            PROTOCOL_HTTP
        }
    }

    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
        // Проверка без сети: интерфейс должен показать ошибку в поле сразу,
        // а не через минуту неудачного подключения.
        self.parse(params)?
            .validate(self.secure)
            .map_err(Into::into)
    }

    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn Outbound>, ProtocolError> {
        let config = self.parse(params)?;
        let outbound = HttpProxyOutbound::new(ctx.id, config, self.secure, ctx.dialer)?;

        // Пробное соединение при подъёме направления. Без него «Подключено»
        // загоралось бы и на прокси, которого нет: постоянного соединения у
        // `CONNECT` не бывает, и неверный адрес выяснился бы только на первом
        // потоке приложения — то есть выглядел бы сломанной страницей, а не
        // ошибкой профиля.
        outbound.verify().await?;
        Ok(Arc::new(outbound))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_a_good_config() {
        let params = json!({ "server": "proxy.example.com:8080" });
        HttpProxyFactory::http()
            .validate(&params)
            .expect("настройки верны");

        let params = json!({
            "server": "proxy.example.com:8443",
            "username": "penguin",
            "password": "secret",
            "tls": { "sni": "real.example.com" }
        });
        HttpProxyFactory::https()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn tls_settings_belong_to_https_only() {
        // Человек ставит «не проверять сертификат» у профиля без TLS и уверен,
        // что TLS есть, — а пароль всё это время уходит открытым текстом.
        let params = json!({ "server": "proxy.example.com:8080", "tls": { "insecure": true } });
        assert!(HttpProxyFactory::http().validate(&params).is_err());
        HttpProxyFactory::https()
            .validate(&params)
            .expect("под TLS это законно");
    }

    #[test]
    fn rejects_a_missing_address() {
        assert!(HttpProxyFactory::http().validate(&json!({})).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let params = json!({ "server": "proxy.example.com:8080", "passwort": "y" });
        assert!(HttpProxyFactory::http().validate(&params).is_err());
    }

    #[test]
    fn protocol_names_are_stable() {
        // Имена стоят в конфигурациях пользователей — менять их нельзя.
        assert_eq!(HttpProxyFactory::http().protocol(), "http");
        assert_eq!(HttpProxyFactory::https().protocol(), "https");
    }
}
