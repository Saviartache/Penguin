//! Проверка и установка по сети.

use std::path::Path;

use crate::error::{UpdateError, UpdateResult};
use crate::flow::install_archive;
use crate::net;
use crate::release::{Available, find_update};
use crate::target::Target;
use crate::version::Version;

const API_LIMIT: u64 = 1024 * 1024;
const SUMS_LIMIT: u64 = 64 * 1024;
const ARCHIVE_LIMIT: u64 = 200 * 1024 * 1024;

/// Страница релизов: `repository` из корневого `Cargo.toml`.
pub fn repository_url() -> &'static str {
    env!("CARGO_PKG_REPOSITORY")
}

/// Адрес API последнего релиза, из того же `repository`.
fn latest_url() -> String {
    let path = repository_url().trim_start_matches("https://github.com/");
    format!("https://api.github.com/repos/{path}/releases/latest")
}

/// Спрашивает GitHub о последнем релизе; `None` — новее нет.
pub fn check() -> UpdateResult<Option<Available>> {
    let target = Target::current().ok_or(UpdateError::UnsupportedTarget)?;
    let json = net::get(&latest_url(), API_LIMIT)?;
    find_update(&json, &Version::current(), &target)
}

/// Скачивает выпуск, сверяет сумму и подменяет `executable`.
pub fn install(available: &Available, executable: &Path) -> UpdateResult<()> {
    let target = Target::current().ok_or(UpdateError::UnsupportedTarget)?;
    let sums = net::get(&available.sums_url, SUMS_LIMIT)?;
    let archive = net::get(&available.archive_url, ARCHIVE_LIMIT)?;
    install_archive(
        &archive,
        &String::from_utf8_lossy(&sums),
        available,
        &target,
        executable,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_api_address_is_derived_from_the_repository() {
        assert_eq!(
            latest_url(),
            "https://api.github.com/repos/Saviartache/penguin/releases/latest"
        );
        assert!(net::check_url(&latest_url()).is_ok());
    }
}
