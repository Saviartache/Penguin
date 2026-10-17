//! Номер версии `major.minor.patch` и сравнение.

use std::fmt;
use std::str::FromStr;

use crate::error::UpdateError;

/// Версия выпуска; предвыпуски (`-rc1`) не разбираются совсем.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// Крупная.
    pub major: u64,
    /// Средняя.
    pub minor: u64,
    /// Мелкая.
    pub patch: u64,
}

impl Version {
    /// Версия этой сборки.
    pub fn current() -> Self {
        // Номер задаёт сам Cargo; не разобрался бы он — упала бы сборка тестов.
        env!("CARGO_PKG_VERSION").parse().unwrap_or(Self {
            major: 0,
            minor: 0,
            patch: 0,
        })
    }
}

impl FromStr for Version {
    type Err = UpdateError;

    /// Принимает и `v0.7.2`: так называются теги.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bad = || UpdateError::BadVersion(text.to_owned());
        let mut parts = text.strip_prefix('v').unwrap_or(text).split('.');
        let mut next = || -> Result<u64, UpdateError> {
            let part = parts.next().ok_or_else(bad)?;
            // `u64::from_str` пропускает `+1`.
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(bad());
            }
            part.parse().map_err(|_| bad())
        };
        let version = Self {
            major: next()?,
            minor: next()?,
            patch: next()?,
        };
        if parts.next().is_some() {
            return Err(bad());
        }
        Ok(version)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        text.parse().expect("версия")
    }

    #[test]
    fn tags_and_plain_numbers_parse() {
        assert_eq!(v("v0.7.2"), v("0.7.2"));
        assert_eq!(v("1.20.3").to_string(), "1.20.3");
    }

    #[test]
    fn comparison_is_numeric_not_textual() {
        assert!(v("0.10.0") > v("0.9.9"));
        assert!(v("1.0.0") > v("0.99.99"));
        assert!(v("0.7.3") > v("0.7.2"));
        assert!(v("0.7.2") == v("v0.7.2"));
    }

    #[test]
    fn anything_else_is_rejected() {
        for text in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "1.2.3-rc1",
            "+1.2.3",
            "1..3",
            "-1.2.3",
        ] {
            assert!(text.parse::<Version>().is_err(), "{text}");
        }
    }

    #[test]
    fn the_running_build_has_a_version() {
        assert!(Version::current() > v("0.0.0"));
    }
}
