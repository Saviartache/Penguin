//! Реестр протоколов: строка из конфига -> фабрика.
//!
//! Единственное место во всей программе, где перечислены протоколы. Всё, что
//! нужно для подключения нового, — одна строка регистрации в `penguin-engine`
//! под своей фичей.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::ProtocolError;
use crate::factory::ProtocolFactory;

/// Набор известных протоколов.
#[derive(Default)]
pub struct ProtocolRegistry {
    factories: HashMap<&'static str, Arc<dyn ProtocolFactory>>,
}

impl ProtocolRegistry {
    /// Пустой реестр.
    pub fn new() -> Self {
        Self::default()
    }

    /// Добавляет протокол.
    ///
    /// Повторная регистрация того же имени заменяет прежнюю запись: так
    /// тесты подставляют поддельный протокол вместо настоящего.
    pub fn register(&mut self, factory: Arc<dyn ProtocolFactory>) -> &mut Self {
        self.factories.insert(factory.protocol(), factory);
        self
    }

    /// Фабрика по имени протокола.
    pub fn get(&self, protocol: &str) -> Result<&Arc<dyn ProtocolFactory>, ProtocolError> {
        self.factories
            .get(protocol)
            .ok_or_else(|| ProtocolError::UnknownProtocol(protocol.to_owned()))
    }

    /// Имена всех зарегистрированных протоколов — для интерфейса и диагностики.
    pub fn protocols(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.factories.keys().copied()
    }
}
