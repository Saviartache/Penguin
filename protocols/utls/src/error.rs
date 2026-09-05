//! Ошибки сборки и разбора.
//!
//! Крейт не ходит в сеть, поэтому большинство его ошибок — это не «сервер не
//! ответил», а «то, что дали на входе, не годится» или «то, что пришло с
//! провода, не по формату». Второе — не редкость и не повод падать: сервер
//! может оборвать поток на середине `ServerHello`, прислать неизвестное
//! расширение или указать длину больше, чем осталось байт. Разбор обязан
//! вернуть ошибку, а не запаниковать (`AGENTS.md` §4.3) — сюда попадает и то,
//! что прочитал бы `unwrap`, не будь он под запретом.

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

    /// Байты `ServerHello` не по формату: обрезаны, испорчены или не то, что
    /// ожидалось (не тот тип сообщения, не та версия записи).
    ///
    /// Не различается на «обрезано» и «испорчено»: клиенту в обоих случаях
    /// нужно одно и то же — оборвать соединение, а не гадать, дочитается ли
    /// оно само.
    #[error("`ServerHello` не по формату: {0}")]
    Malformed(String),

    /// Генератор ключа `key_share` отказал.
    ///
    /// В `ring` это происходит только при исчерпании системного источника
    /// случайности — событие настолько редкое, что для него нет отдельного
    /// восстановимого пути, только отказ.
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

    /// SNI требует доменное имя: Reality и остальные протоколы с отпечатком
    /// подделывают чужой сайт, а у сайта есть имя, а не только адрес.
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
            // Не по формату — значит, на том конце не то, что ждали: обычный
            // сайт вместо Reality, оборванная запись. Само оно не исправится,
            // и это решение из того же ряда, что у `penguin-transport`
            // (`TransportError::Malformed`): повторять нечего.
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
        // Испорченный или чужой ответ сам себя не исправит: повторять нечего.
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
