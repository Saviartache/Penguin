//! Обновление: проверка и установка.
//!
//! Единственное место клиента, ходящее на GitHub. Окно запускает эту команду как отдельный
//! процесс и читает `--json`: в сеть мимо канала управления оно само не ходит.

use anyhow::{Context, Result};
use penguin_update::{Available, CheckReport, Version};
use serde::Serialize;

use crate::args::UpdateCommand;
use crate::output::{Format, emit, ok};

/// Итог установки.
#[derive(Debug, Serialize)]
struct Installed {
    version: String,
}

/// Выполняет команду.
pub fn run(command: &UpdateCommand, format: Format) -> Result<()> {
    match command {
        UpdateCommand::Check => check(format),
        UpdateCommand::Install => install(format),
    }
}

fn check(format: Format) -> Result<()> {
    let report = CheckReport {
        current: Version::current().to_string(),
        available: penguin_update::check()?,
    };
    emit(format, &report, render);
    Ok(())
}

fn render(report: &CheckReport) -> String {
    match &report.available {
        Some(found) => format!(
            "Установлена {}, доступна {}: {}",
            report.current, found.version, found.page_url
        ),
        None => ok(format!("Установлена {}, обновлений нет", report.current)),
    }
}

fn install(format: Format) -> Result<()> {
    let Some(found) = penguin_update::check()? else {
        emit(
            format,
            &Installed {
                version: Version::current().to_string(),
            },
            |_| ok("Обновлений нет"),
        );
        return Ok(());
    };
    install_found(&found)?;
    emit(
        format,
        &Installed {
            version: found.version.clone(),
        },
        |done| ok(format!("Установлена {}", done.version)),
    );
    Ok(())
}

fn install_found(found: &Available) -> Result<()> {
    let executable = std::env::current_exe().context("не удалось узнать свой путь")?;
    penguin_update::install(found, &executable)
        .with_context(|| format!("не удалось установить {}", found.version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_names_both_versions_and_the_page() {
        let report = CheckReport {
            current: "0.7.2".into(),
            available: Some(Available {
                version: "0.8.0".into(),
                page_url: "https://github.com/x/y/releases/tag/v0.8.0".into(),
                archive_name: String::new(),
                archive_url: String::new(),
                sums_url: String::new(),
            }),
        };
        let text = render(&report);
        assert!(text.contains("0.7.2") && text.contains("0.8.0") && text.contains("releases/tag"));
    }

    #[test]
    fn no_release_reads_as_up_to_date() {
        let text = render(&CheckReport {
            current: "0.7.2".into(),
            available: None,
        });
        assert!(text.contains("обновлений нет"), "{text}");
    }

    #[test]
    fn the_json_the_window_reads_round_trips() {
        let report = CheckReport {
            current: "0.7.2".into(),
            available: None,
        };
        let json = serde_json::to_string(&report).expect("json");
        assert_eq!(
            serde_json::from_str::<CheckReport>(&json).expect("разбор"),
            report
        );
    }
}
