//! Ошибки сборки и разбора.
//!

use penguin_core::address::Address;
use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции этого крейта.
pub type UtlsResult<T> = Result<T, UtlsError>;

/// Что пошло не так при сборке `ClientHello` или разборе `ServerHello`.
#[derive(Debug, Error)]
pub enum UtlsError {
    /// Входные данные для сборки не годятся: не то имя, не тот отпечаток.
    #[error("настройки uTLS: {0}")]
    Config(String),

    /// `ServerHello` обрезан, испорчен или не того типа.
    #[error("`ServerHello` не по формату: {0}")]
    Malformed(String),

    /// Генератор ключа `key_share` отказал.
    #[error("не удалось сгенерировать пару ключей: {0}")]
    KeyGeneration(&'static str),
}

impl UtlsError {
    /// Настройки сборки не годятся.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// `ServerHello` не по формату.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// SNI требует доменное имя.
    pub fn sni_requires_domain(address: &Address) -> Self {
        Self::config(format!(
            "SNI `{address}` — не доменное имя: отпечаток браузера подделывает \
             сайт по имени, а не по адресу"
        ))
    }
}

impl From<UtlsError> for ProtocolError {
    fn from(err: UtlsError) -> Self {
        match err {
            UtlsError::Config(message) => Self::InvalidConfig(message),
            err @ UtlsError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            err @ UtlsError::KeyGeneration(_) => Self::InvalidConfig(err.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_server_hello_is_not_retried() {
        let err: ProtocolError = UtlsError::malformed("слишком короткая запись").into();
        assert!(!err.is_retryable());
        assert!(err.to_string().contains("слишком короткая запись"));
    }

    #[test]
    fn a_numeric_sni_is_a_config_error() {
        let address = Address::Ip("203.0.113.5".parse().expect("адрес"));
        let err: ProtocolError = UtlsError::sni_requires_domain(&address).into();
        assert!(!err.is_retryable());
        assert!(err.to_string().contains("203.0.113.5"));
    }
}
