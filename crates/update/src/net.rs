//! HTTPS к GitHub: только свои узлы, переходы проверяются вручную.

use std::time::Duration;

use ureq::Agent;
use ureq::http::header::LOCATION;

use crate::error::{UpdateError, UpdateResult};

/// Узлы, с которых можно что-то брать: API, страница релиза и хранилище вложений
/// (`release-assets.` — новый адрес того же хранилища, на который GitHub перенаправляет сейчас).
const HOSTS: [&str; 4] = [
    "api.github.com",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

/// Переходов не больше: API → github.com → хранилище.
const MAX_REDIRECTS: usize = 4;

/// Допустим ли адрес: HTTPS, один из [`HOSTS`], без учётных данных и порта.
pub(crate) fn check_url(url: &str) -> UpdateResult<()> {
    let forbidden = || UpdateError::ForbiddenUrl(url.chars().take(120).collect());
    let rest = url.strip_prefix("https://").ok_or_else(forbidden)?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if HOSTS.contains(&host) {
        Ok(())
    } else {
        Err(forbidden())
    }
}

fn agent() -> Agent {
    Agent::config_builder()
        .https_only(true)
        // Переходы идут через `check_url`, а не сами.
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(300)))
        .user_agent(concat!("penguin/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// Скачивает `url` целиком, но не больше `limit` байт.
pub(crate) fn get(url: &str, limit: u64) -> UpdateResult<Vec<u8>> {
    let agent = agent();
    let mut url = url.to_owned();
    for _ in 0..=MAX_REDIRECTS {
        check_url(&url)?;
        let mut response = agent
            .get(&url)
            .header(
                "Accept",
                "application/vnd.github+json, application/octet-stream",
            )
            .call()
            .map_err(|err| UpdateError::Network(err.to_string()))?;

        let status = response.status();
        if status.is_redirection() {
            url = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| UpdateError::Network(format!("{status} без Location")))?
                .to_owned();
            continue;
        }
        if !status.is_success() {
            return Err(UpdateError::Network(format!("{url}: {status}")));
        }
        return response
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_vec()
            .map_err(|err| match err {
                ureq::Error::BodyExceedsLimit(_) => UpdateError::TooLarge { limit },
                other => UpdateError::Network(other.to_string()),
            });
    }
    Err(UpdateError::Network("слишком много переходов".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_hosts_over_https_are_allowed() {
        for url in [
            "https://api.github.com/repos/Saviartache/penguin/releases/latest",
            "https://github.com/Saviartache/penguin/releases/download/v1/a.zip",
            "https://objects.githubusercontent.com/github-production-release-asset/1?X=1",
            "https://release-assets.githubusercontent.com/x",
            "https://github.com",
        ] {
            assert!(check_url(url).is_ok(), "{url}");
        }
    }

    #[test]
    fn everything_else_is_forbidden() {
        for url in [
            "http://github.com/a",
            "https://evil.example/a",
            "https://github.com.evil.example/a",
            "https://evilgithub.com/a",
            "https://github.com@evil.example/a",
            "https://github.com:8443/a",
            "https://evil.example/?https://github.com/",
            "https://evil.example#@github.com/",
            "ftp://github.com/a",
            "//github.com/a",
            "file:///etc/passwd",
            "",
        ] {
            assert!(
                matches!(check_url(url), Err(UpdateError::ForbiddenUrl(_))),
                "{url}"
            );
        }
    }
}
