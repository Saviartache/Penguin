//! Разбор ответа `GET /repos/{repo}/releases/latest`.

use serde::{Deserialize, Serialize};

use crate::error::{UpdateError, UpdateResult};
use crate::target::Target;
use crate::version::Version;

/// Имя файла сумм в релизе.
pub(crate) const SUMS_NAME: &str = "SHA256SUMS";

/// Новый выпуск, пригодный для этой системы.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Available {
    /// Номер без `v`.
    pub version: String,
    /// Страница выпуска.
    pub page_url: String,
    /// Имя архива.
    pub archive_name: String,
    /// Откуда качать архив.
    pub archive_url: String,
    /// Откуда качать `SHA256SUMS`.
    pub sums_url: String,
}

/// Ответ `penguin update check --json`: его читает окно.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckReport {
    /// Версия запущенной программы.
    pub current: String,
    /// Новый выпуск, если есть.
    pub available: Option<Available>,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// Ищет в ответе API выпуск новее `current`; `None` — обновляться не на что.
pub fn find_update(
    json: &[u8],
    current: &Version,
    target: &Target,
) -> UpdateResult<Option<Available>> {
    let release: Release =
        serde_json::from_slice(json).map_err(|err| UpdateError::BadResponse(err.to_string()))?;
    if release.draft || release.prerelease {
        return Ok(None);
    }
    let version: Version = release.tag_name.parse()?;
    if version <= *current {
        return Ok(None);
    }

    let archive_name = target.archive_name(&version);
    let url_of = |name: &str| {
        release
            .assets
            .iter()
            .find(|asset| asset.name == name)
            .map(|asset| asset.browser_download_url.clone())
            .ok_or_else(|| UpdateError::NoAsset(name.to_owned()))
    };
    Ok(Some(Available {
        version: version.to_string(),
        page_url: release.html_url.clone(),
        archive_url: url_of(&archive_name)?,
        sums_url: url_of(SUMS_NAME)?,
        archive_name,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LATEST: &[u8] = include_bytes!("../tests/fixtures/latest.json");

    fn version(text: &str) -> Version {
        text.parse().expect("версия")
    }

    fn target(os: &str, arch: &str) -> Target {
        Target::of(os, arch).expect("поставка")
    }

    #[test]
    fn a_newer_release_yields_this_systems_archive() {
        let found = find_update(LATEST, &version("0.7.2"), &target("macos", "aarch64"))
            .expect("разбор")
            .expect("есть обновление");

        assert_eq!(found.version, "0.8.0");
        assert_eq!(found.archive_name, "penguin-0.8.0-macos-arm64.zip");
        assert!(
            found
                .archive_url
                .ends_with("/v0.8.0/penguin-0.8.0-macos-arm64.zip")
        );
        assert!(found.sums_url.ends_with("/v0.8.0/SHA256SUMS"));
        assert_eq!(
            found.page_url,
            "https://github.com/Saviartache/penguin/releases/tag/v0.8.0"
        );
    }

    #[test]
    fn each_system_gets_its_own_archive() {
        for (os, arch, name) in [
            ("windows", "x86_64", "penguin-0.8.0-windows-x64.zip"),
            ("linux", "x86_64", "penguin-0.8.0-linux-x64.tar.gz"),
            ("macos", "x86_64", "penguin-0.8.0-macos-x64.zip"),
        ] {
            let found = find_update(LATEST, &version("0.7.2"), &target(os, arch))
                .expect("разбор")
                .expect("есть обновление");
            assert_eq!(found.archive_name, name);
        }
    }

    #[test]
    fn the_same_or_an_older_release_is_not_an_update() {
        for current in ["0.8.0", "0.8.1", "1.0.0"] {
            let found = find_update(LATEST, &version(current), &target("linux", "x86_64"));
            assert_eq!(found.expect("разбор"), None, "{current}");
        }
    }

    #[test]
    fn drafts_and_prereleases_are_skipped() {
        for flag in ["draft", "prerelease"] {
            let text = String::from_utf8_lossy(LATEST)
                .replace(&format!("\"{flag}\": false"), &format!("\"{flag}\": true"));
            let found = find_update(
                text.as_bytes(),
                &version("0.7.2"),
                &target("linux", "x86_64"),
            );
            assert_eq!(found.expect("разбор"), None, "{flag}");
        }
    }

    #[test]
    fn a_release_without_our_archive_is_an_error_not_silence() {
        let text = String::from_utf8_lossy(LATEST).replace("linux-x64.tar.gz\"", "other.tar.gz\"");
        let found = find_update(
            text.as_bytes(),
            &version("0.7.2"),
            &target("linux", "x86_64"),
        );
        assert!(matches!(found, Err(UpdateError::NoAsset(_))), "{found:?}");
    }

    #[test]
    fn a_release_without_sums_is_refused() {
        let text = String::from_utf8_lossy(LATEST).replace("\"SHA256SUMS\"", "\"other\"");
        let found = find_update(
            text.as_bytes(),
            &version("0.7.2"),
            &target("linux", "x86_64"),
        );
        assert!(matches!(found, Err(UpdateError::NoAsset(name)) if name == SUMS_NAME));
    }

    #[test]
    fn garbage_is_a_bad_response() {
        let found = find_update(b"<html>", &version("0.7.2"), &target("linux", "x86_64"));
        assert!(matches!(found, Err(UpdateError::BadResponse(_))));
    }
}
