//! Апстримы, стратегия, таймауты.
//!
//! Схема живёт в `penguin-config`; здесь она переэкспортируется и дополняется выводимым.

use std::time::Duration;

pub use penguin_config::schema::dns::{DnsConfig, DnsMode, Upstream};

/// Ожидание ответа от одного апстрима: две попытки укладываются в пятисекундную перепосылку приложения.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

/// TTL подставных адресов: короткий, чтобы приложение не пережило соответствие адреса и имени.
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
        let config = DnsConfig {
            mode: DnsMode::System,
            upstreams: Vec::new(),
            ..DnsConfig::default()
        };
        validate(&config).expect("режим `system` апстримов не требует");
    }

    #[test]
    fn empty_bootstrap_is_rejected() {
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
    fn two_attempts_fit_before_the_retransmission() {
        const { assert!(UPSTREAM_TIMEOUT.as_secs() * 2 < 5) };
    }

    #[test]
    fn fake_ip_ttl_is_short() {
        const { assert!(FAKE_IP_TTL <= 60) };
    }
}
