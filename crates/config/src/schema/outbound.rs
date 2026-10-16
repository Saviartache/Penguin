//! `RawOutbound` — идентификатор протокола плюс непрозрачные параметры.
//! Схему параметров знает только сам протокол.

use serde::{Deserialize, Serialize};

/// Исходящее направление как в файле; `protocol` вынут, остальное в `params`.
///
/// ```toml
/// [profiles.outbound]
/// protocol = "hysteria2"
/// server   = "example.com:443"
/// password = "..."
/// up_mbps  = 100
/// ```
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

    /// Значение поля верхнего уровня.
    pub fn field(&self, name: &str) -> Option<&serde_json::Value> {
        self.params.get(name)
    }
}
