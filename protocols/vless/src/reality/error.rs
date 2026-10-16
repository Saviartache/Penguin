//! Ошибки рукопожатия Reality.
//!
//! Не узнавший клиента сервер молча пересылает `ClientHello` настоящему сайту, поэтому
//! [`RealityError::NotRecognized`] неотличим от подмены и от ошибки в `public_key`/`short_id`.

use thiserror::Error;

/// Что пошло не так при рукопожатии Reality.
#[derive(Debug, Error)]
pub enum RealityError {
    /// Настройки не разбираются или противоречивы.
    #[error("настройки Reality: {0}")]
    Config(String),

    /// Сервер прислал не TLS 1.3 или что-то, не похожее на `ServerHello`.
    #[error("ответ не по формату Reality: {0}")]
    Malformed(String),

    /// `ServerHello.key_share` — не `X25519`: `HelloRetryRequest` или не Reality.
    #[error("ServerHello предложил группу {0:#06x} вместо X25519 — Reality с ней не работает")]
    UnexpectedGroup(u16),

    /// Сервер выбрал версию или шифр за пределами TLS 1.3.
    #[error("сервер согласился не на TLS 1.3: {0}")]
    UnsupportedNegotiation(String),

    /// Криптографическая операция отказала; на практике — запись испорчена или не тем ключом.
    #[error("криптографическая операция Reality отказала: {0}")]
    Crypto(&'static str),

    /// Сертификат сервера не разбирается как X.509 DER.
    #[error("сертификат сервера не разбирается: {0}")]
    Certificate(&'static str),

    /// Сервер не подтвердил себя как Reality; три причины в тексте неразличимы по построению.
    #[error(
        "сервер не подтвердил себя как Reality: либо `public_key`/`short_id` не подходят, \
         либо мы достучались до обычного сайта, либо канал кем-то подменён — отличить эти \
         случаи нельзя"
    )]
    NotRecognized,

    /// Ключевое расписание TLS 1.3 отказало (`ring` не принял длину вывода).
    #[error("ключевое расписание TLS 1.3 отказало")]
    KeySchedule,

    /// `Finished` сервера не совпал с посчитанным (RFC 8446 §4.4.4); сертификат к этому
    /// моменту уже прошёл HMAC-проверку, так что это не [`Self::NotRecognized`].
    #[error(
        "Finished сервера не совпал с посчитанным — транскрипт рукопожатия подменён или ключи разошлись"
    )]
    FinishedMismatch,

    /// Сервер запросил `KeyUpdate` (RFC 8446 §4.6.3): не реализовано, канал закрывается.
    #[error("сервер запросил KeyUpdate — обновление ключей не реализовано, канал закрывается")]
    KeyUpdateNotSupported,

    /// Сервер прислал `alert` вместо прикладных данных.
    #[error("сервер прислал TLS alert (уровень {level:#04x}, описание {description:#04x})")]
    Alert {
        /// Байт уровня тревоги (`warning` = 1, `fatal` = 2).
        level: u8,
        /// Байт описания (RFC 8446 §6.2).
        description: u8,
    },

    /// Соединение оборвалось во время рукопожатия.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_recognized_names_all_three_indistinguishable_causes() {
        let text = RealityError::NotRecognized.to_string();
        assert!(text.contains("public_key"));
        assert!(text.contains("обычного сайта"));
        assert!(text.contains("подменён"));
    }
}
