//! `RawOutbound` — идентификатор протокола плюс непрозрачные параметры.
//! Схему параметров знает только сам протокол.
//!
//! Это и есть та развязка, из-за которой добавление протокола не трогает
//! общий конфиг. Если бы `penguin-config` знал поля Hysteria 2, то знал бы и
//! поля VLESS, и поля WireGuard, и каждый новый протокол правил бы файл,
//! который читают все.

use serde::{Deserialize, Serialize};

/// Описание исходящего направления в том виде, в каком оно лежит в файле.
///
/// ```toml
/// [profiles.outbound]
/// protocol = "hysteria2"
/// server   = "example.com:443"
/// password = "..."
/// up_mbps  = 100
/// ```
///
/// Поле `protocol` вынуто, всё остальное собрано в `params` и передаётся
/// фабрике протокола как есть.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawOutbound {
    /// Имя протокола: `hysteria2`.
    pub protocol: String,
    /// Всё остальное. Разбирает только сам протокол.
    #[serde(flatten)]
    pub params: serde_json::Value,
}

impl RawOutbound {
    /// Собирает описание.
    pub fn new(protocol: impl Into<String>, params: serde_json::Value) -> Self {
        Self {
            protocol: protocol.into(),
            params,
        }
    }

    /// Значение поля верхнего уровня — для интерфейса, которому надо
    /// показать адрес сервера, не разбирая параметры целиком.
    pub fn field(&self, name: &str) -> Option<&serde_json::Value> {
        self.params.get(name)
    }
}
