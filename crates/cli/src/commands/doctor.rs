//! Проверка окружения: драйвер, права, маршруты, DNS.
//!
//! Первое, что стоит запустить, когда «не работает». Проверки идут снизу
//! вверх — от того, что должно быть на месте всегда, к тому, что нужно
//! только тоннелю, — и каждая отвечает не «да/нет», а тем, что делать
//! дальше.

use anyhow::Result;
use penguin_config::{ConfigStore, RootConfig};
use serde::Serialize;

use crate::output::{Format, emit, fail, ok, table};

/// Исход одной проверки.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Всё в порядке.
    Ok,
    /// Работать будет, но не всё.
    Warning,
    /// Не будет работать.
    Failed,
}

/// Одна проверка.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Что проверяли.
    pub name: String,
    /// Что получилось.
    pub status: Status,
    /// Подробности и что делать.
    pub detail: String,
}

impl Check {
    fn pass(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            status: Status::Ok,
            detail: detail.into(),
        }
    }

    fn warn(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            status: Status::Warning,
            detail: detail.into(),
        }
    }

    fn fail(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            status: Status::Failed,
            detail: detail.into(),
        }
    }
}

/// Отчёт проверки.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Проверки по порядку.
    pub checks: Vec<Check>,
    /// Всё ли готово к работе.
    pub healthy: bool,
}

/// Выполняет проверки.
pub fn run(store: &ConfigStore, config: &RootConfig, format: Format) -> Result<()> {
    let mut checks = vec![
        check_config(store, config),
        check_profiles(config),
        check_rules(config),
        check_protocols(),
    ];
    checks.push(check_driver());
    checks.push(check_privileges());

    let healthy = checks.iter().all(|c| c.status != Status::Failed);
    let report = Report { checks, healthy };

    emit(format, &report, render);
    Ok(())
}

fn check_config(store: &ConfigStore, config: &RootConfig) -> Check {
    let path = store.paths().config_file();
    // Общий это каталог или профиль пользователя — не мелочь: служба читает
    // общий, и настройки, положенные не туда, просто не подействуют.
    let shared = penguin_config::Paths::machine()
        .is_some_and(|machine| store.paths().config_dir() == machine.config_dir());

    let whose = if shared {
        "общий каталог — его читает и служба"
    } else {
        "профиль пользователя — службе он не виден"
    };

    if path.exists() {
        Check::pass(
            "настройки",
            format!("{} ({whose}), схема {}", path.display(), config.version),
        )
    } else {
        Check::warn(
            "настройки",
            format!(
                "файла нет — используются умолчания; создайте {}",
                path.display()
            ),
        )
    }
}

fn check_profiles(config: &RootConfig) -> Check {
    if config.profiles.is_empty() {
        return Check::fail("профили", "не задано ни одного — подключаться некуда");
    }

    let active = config.active().map(|p| p.name.clone()).unwrap_or_default();
    Check::pass(
        "профили",
        format!("{}, активный — `{active}`", config.profiles.len()),
    )
}

fn check_rules(config: &RootConfig) -> Check {
    use penguin_core::id::OutboundId;
    use penguin_router::engine::Router;
    use penguin_router::ruleset::CompileContext;

    match Router::new(
        &config.routing,
        OutboundId::direct(),
        &CompileContext::default(),
    ) {
        Ok(router) => Check::pass(
            "правила",
            format!(
                "{}, режим `{}`",
                router.rule_count(),
                config.routing.mode.as_str()
            ),
        ),
        // Правило, которое не собирается, — это правило, которое не работает.
        // Молча пропустить его нельзя: трафик пойдёт не туда.
        Err(err) => Check::fail("правила", err.to_string()),
    }
}

fn check_protocols() -> Check {
    use std::sync::Arc;

    use penguin_dns::resolver::SystemResolver;
    use penguin_engine::direct::SystemDialer;
    use penguin_engine::outbounds::OutboundPool;

    let pool = OutboundPool::new(Arc::new(SystemDialer::new(Arc::new(SystemResolver))));
    let protocols = pool.protocols();

    if protocols.is_empty() {
        Check::fail("протоколы", "клиент собран без единого протокола")
    } else {
        Check::pass("протоколы", protocols.join(", "))
    }
}

fn check_driver() -> Check {
    // Самая частая причина «тоннель не включается» на Windows: `wintun.dll` в
    // поставку системы не входит. Узнать об этом здесь дешевле, чем из ошибки
    // посреди подключения.
    match penguin_tun::driver_available() {
        Ok(()) => Check::pass("драйвер", "на месте — режим тоннеля доступен"),
        // Не `fail`: прокси-режим без драйвера работает целиком, и объявлять
        // клиент неисправным из-за недоступного тоннеля неверно.
        Err(err) => Check::warn(
            "драйвер",
            format!("{err}; прокси-режим работает и без него"),
        ),
    }
}

fn check_privileges() -> Check {
    // Прокси-режиму права не нужны вовсе; они понадобятся тоннелю. Сказать об
    // этом стоит заранее — чтобы «не работает» не оказалось «запущено не от
    // администратора».
    if penguin_platform::is_elevated() {
        Check::pass("права", "повышенные — тоннель доступен")
    } else {
        Check::warn(
            "права",
            "обычные — прокси-режим работает, тоннелю понадобится запуск от администратора",
        )
    }
}

fn render(report: &Report) -> String {
    let rows: Vec<Vec<String>> = report
        .checks
        .iter()
        .map(|check| {
            let mark = match check.status {
                Status::Ok => "✓",
                Status::Warning => "!",
                Status::Failed => "✗",
            };
            vec![mark.to_owned(), check.name.clone(), check.detail.clone()]
        })
        .collect();

    let mut out = table(&["", "проверка", "подробности"], &rows);
    out.push_str("\n\n");
    out.push_str(&if report.healthy {
        ok("клиент готов к работе")
    } else {
        fail("есть неисправности — см. выше")
    });
    out
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::outbound::RawOutbound;
    use penguin_config::schema::profile::Profile;
    use penguin_config::schema::rule::RuleConfig;
    use serde_json::json;

    use super::*;

    fn config_with_profile() -> RootConfig {
        let mut config = RootConfig::default();
        config.profiles.push(Profile::new(
            "home",
            "Домашний",
            RawOutbound::new(
                "hysteria2",
                json!({ "server": "example.com:443", "auth": "x" }),
            ),
        ));
        config
    }

    #[test]
    fn empty_config_fails_on_profiles() {
        let check = check_profiles(&RootConfig::default());
        assert_eq!(check.status, Status::Failed);
        assert!(check.detail.contains("подключаться некуда"));
    }

    #[test]
    fn profile_check_names_the_active_one() {
        let check = check_profiles(&config_with_profile());
        assert_eq!(check.status, Status::Ok);
        assert!(check.detail.contains("Домашний"));
    }

    #[test]
    fn broken_rule_fails_the_report() {
        let mut config = config_with_profile();
        let rules: Vec<RuleConfig> = serde_json::from_value(json!([
            { "id": "плохое", "when": { "dest_ip": ["не адрес"] }, "action": "direct" }
        ]))
        .expect("правила разбираются");
        config.routing.rules = rules;

        // Правило, которое не собирается, — это правило, которое не работает.
        assert_eq!(check_rules(&config).status, Status::Failed);
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn protocols_are_listed() {
        let check = check_protocols();
        assert_eq!(check.status, Status::Ok);
        assert!(check.detail.contains("hysteria2"));
    }

    #[test]
    fn report_renders_a_verdict() {
        let report = Report {
            checks: vec![Check::pass("а", "хорошо"), Check::warn("б", "так себе")],
            healthy: true,
        };
        let rendered = render(&report);
        assert!(rendered.contains("готов к работе"));
        assert!(rendered.contains('!'));
    }

    #[test]
    fn failure_is_visible_in_the_verdict() {
        let report = Report {
            checks: vec![Check::fail("а", "плохо")],
            healthy: false,
        };
        assert!(render(&report).contains("неисправности"));
    }
}
