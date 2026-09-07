//! Апстримы, стратегия, таймауты.
//!
//! Сама схема живёт в `penguin-config` — её читают и пишут в общий файл
//! настроек. Здесь она переэкспортируется, чтобы крейт не тащил через себя
//! чужие пути, и добавляется то, что из настроек выводится.

use std::time::Duration;

pub use penguin_config::schema::dns::{DnsConfig, DnsMode, Upstream};

/// Сколько ждать ответа от одного апстрима.
///
/// Приложение обычно ждёт пять секунд и перепосылает запрос. Уложиться надо
/// заметно раньше, иначе перепосылка приходит раньше нашего ответа и запросов
/// становится вдвое больше. Считать надо не по одному апстриму: список — это
/// запасные пути друг для друга, и опрашиваются они подряд, так что молчащий
/// первый добавляет к ожиданию целый таймаут. Две секунды оставляют место
/// ровно на две попытки внутри окна перепосылки.
///
/// Значение общее для всех апстримов, включая DNS-over-TLS с его
/// рукопожатием: соединение и рукопожатие — это три-четыре RTT, и на любом
/// пригодном пути они укладываются в тот же бюджет. Там, где не укладываются,
/// ждать дольше уже бессмысленно — ответ всё равно опоздает.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

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
    fn two_attempts_fit_before_the_retransmission() {
        // Приложение перепошлёт через пять секунд; в это окно должны влезать
        // молчащий первый апстрим и ответивший второй.
        const { assert!(UPSTREAM_TIMEOUT.as_secs() * 2 < 5) };
    }

    #[test]
    fn fake_ip_ttl_is_short() {
        // Долгий кэш у приложения пережил бы соответствие адреса и имени.
        const { assert!(FAKE_IP_TTL <= 60) };
    }
}
