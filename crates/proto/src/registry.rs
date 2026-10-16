//! Реестр протоколов: строка из конфига -> фабрика.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::ProtocolError;
use crate::factory::ProtocolFactory;
use crate::packet::PacketFactory;

/// Набор известных протоколов.
#[derive(Default)]
pub struct ProtocolRegistry {
    factories: HashMap<&'static str, Arc<dyn ProtocolFactory>>,
    /// Протоколы уровня пакетов (другая фабрика и направление).
    packets: HashMap<&'static str, Arc<dyn PacketFactory>>,
}

impl ProtocolRegistry {
    /// Пустой реестр.
    pub fn new() -> Self {
        Self::default()
    }

    /// Добавляет протокол; то же имя заменяет прежнюю запись.
    pub fn register(&mut self, factory: Arc<dyn ProtocolFactory>) -> &mut Self {
        self.factories.insert(factory.protocol(), factory);
        self
    }

    /// Добавляет протокол уровня пакетов.
    pub fn register_packet(&mut self, factory: Arc<dyn PacketFactory>) -> &mut Self {
        self.packets.insert(factory.protocol(), factory);
        self
    }

    /// Фабрика по имени протокола.
    pub fn get(&self, protocol: &str) -> Result<&Arc<dyn ProtocolFactory>, ProtocolError> {
        self.factories
            .get(protocol)
            .ok_or_else(|| ProtocolError::UnknownProtocol(protocol.to_owned()))
    }

    /// Фабрика протокола уровня пакетов, если это он.
    pub fn get_packet(&self, protocol: &str) -> Option<&Arc<dyn PacketFactory>> {
        self.packets.get(protocol)
    }

    /// Проверяет параметры протокола любого уровня.
    pub fn validate(
        &self,
        protocol: &str,
        params: &serde_json::Value,
    ) -> Result<(), ProtocolError> {
        if let Some(factory) = self.packets.get(protocol) {
            return factory.validate(params);
        }
        self.get(protocol)?.validate(params)
    }

    /// Имена всех зарегистрированных протоколов обоих уровней.
    pub fn protocols(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.factories.keys().chain(self.packets.keys()).copied()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::*;
    use crate::factory::BuildContext;
    use crate::outbound::Outbound;
    use crate::packet::{PacketFactory, PacketOutbound};

    /// Потоковый протокол, который ничего не собирает.
    struct Stream;

    #[async_trait]
    impl ProtocolFactory for Stream {
        fn protocol(&self) -> &'static str {
            "поток"
        }

        fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
            match params.get("ok") {
                Some(_) => Ok(()),
                None => Err(ProtocolError::InvalidConfig("нет поля `ok`".to_owned())),
            }
        }

        async fn build(
            &self,
            _ctx: BuildContext,
            _params: &serde_json::Value,
        ) -> Result<Arc<dyn Outbound>, ProtocolError> {
            Err(ProtocolError::Unsupported("тест не поднимает направлений"))
        }
    }

    /// Пакетный протокол, который тоже ничего не собирает.
    struct Packets;

    #[async_trait]
    impl PacketFactory for Packets {
        fn protocol(&self) -> &'static str {
            "пакеты"
        }

        fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
            match params.get("ok") {
                Some(_) => Ok(()),
                None => Err(ProtocolError::InvalidConfig("нет поля `ok`".to_owned())),
            }
        }

        async fn build(
            &self,
            _ctx: BuildContext,
            _params: &serde_json::Value,
        ) -> Result<Arc<dyn PacketOutbound>, ProtocolError> {
            Err(ProtocolError::Unsupported("тест не поднимает направлений"))
        }
    }

    fn registry() -> ProtocolRegistry {
        let mut registry = ProtocolRegistry::new();
        registry.register(Arc::new(Stream));
        registry.register_packet(Arc::new(Packets));
        registry
    }

    #[test]
    fn both_levels_are_listed_together() {
        let registry = registry();
        let mut names: Vec<&str> = registry.protocols().collect();
        names.sort_unstable();
        assert_eq!(names, vec!["пакеты", "поток"]);
    }

    #[test]
    fn validation_finds_the_protocol_at_either_level() {
        let registry = registry();
        let good = serde_json::json!({ "ok": true });
        let bad = serde_json::json!({});

        for name in ["поток", "пакеты"] {
            registry.validate(name, &good).expect("настройки верны");
            assert!(registry.validate(name, &bad).is_err(), "{name}");
        }

        let err = registry
            .validate("телепатия", &good)
            .expect_err("такого протокола нет");
        assert!(err.to_string().contains("телепатия"));
    }

    #[test]
    fn a_packet_protocol_is_not_mistaken_for_a_stream_one() {
        let registry = registry();
        assert!(registry.get("пакеты").is_err());
        assert!(registry.get_packet("пакеты").is_some());
        assert!(registry.get_packet("поток").is_none());
    }
}
