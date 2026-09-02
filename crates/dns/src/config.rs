//! Апстримы, стратегия, таймауты.
//!
//! Сама схема живёт в `penguin-config` — её читают и пишут в общий файл
//! настроек. Здесь она переэкспортируется, чтобы крейт не тащил через себя
//! чужие пути, и добавляется то, что из настроек выводится.

pub use penguin_config::schema::dns::{DnsConfig, DnsMode, Upstream};

/// Сколько ждать ответа приложению, прежде чем сдаться.
///
/// Приложения обычно ждут пять секунд и перепосылают. Уложиться надо
/// заметно раньше, иначе перепосылка приходит раньше нашего ответа, и
/// запросов становится вдвое больше.
pub const QUERY_TIMEOUT_SECS: u64 = 3;

/// TTL, с которым отдаются подставные адреса.
///
/// Короткий намеренно: соответствие адреса и имени живёт минуты, и долгий
/// кэш у приложения пережил бы его — приложение соединялось бы с адресом,
/// имя которого мы уже забыли.
pub const FAKE_IP_TTL: u32 = 10;

/// Проверяет настройки DNS.
pub fn validate(config: &DnsConfig) -> crate::error::DnsResult<()> {
    use crate::error::DnsError;

    if config.upstreams.is_empty() && config.mode != DnsMode::System {
        return Err(DnsError::Config(
            "не задано ни одного апстрима DNS — разрешать имена будет некому".to_owned(),
        ));
    }

    if config.bootstrap.is_empty() {
        return Err(DnsError::Config(
            "не задан загрузочный апстрим — имя сервера не разрешится".to_owned(),
        ));
    }

    if config.mode == DnsMode::FakeIp {
        // Подсеть разбирается заранее: ошибка в ней означает, что клиент
        // поднимется и перестанет разрешать имена вовсе.
        crate::fakeip::FakeIpPool::parse(&config.fake_ip_range)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        validate(&DnsConfig::default()).expect("умолчания корректны");
    }

    #[test]
    fn empty_upstreams_are_rejected() {
        let config = DnsConfig {
            upstreams: Vec::new(),
            ..DnsConfig::default()
        };
        assert!(validate(&config).is_err());
    }

    #[test]
    fn system_mode_needs_no_upstreams() {
        // В этом режиме клиент в разрешение имён не вмешивается вовсе.
        let config = DnsConfig {
            mode: DnsMode::System,
            upstreams: Vec::new(),
            ..DnsConfig::default()
        };
        validate(&config).expect("режим `system` апстримов не требует");
    }

    #[test]
    fn empty_bootstrap_is_rejected() {
        // Без загрузочного апстрима не разрешится имя самого сервера, и
        // тоннель не поднимется никогда.
        let config = DnsConfig {
            bootstrap: Vec::new(),
            ..DnsConfig::default()
        };
        assert!(validate(&config).is_err());
    }

    #[test]
    fn broken_fake_ip_range_is_caught_early() {
        let config = DnsConfig {
            fake_ip_range: "не подсеть".to_owned(),
            ..DnsConfig::default()
        };
        assert!(validate(&config).is_err());
    }

    #[test]
    fn fake_ip_ttl_is_short() {
        // Долгий кэш у приложения пережил бы соответствие адреса и имени.
        const { assert!(FAKE_IP_TTL <= 60) };
    }
}
