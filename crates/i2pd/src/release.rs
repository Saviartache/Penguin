//! Какой i2pd запускается: версия, имя файла в релизе и его SHA-256.
//!
//! Суммы — из `SHA256SUMS` релиза [`TAG`], собранного `.github/workflows/i2pd.yml`.
//! Новая версия i2pd — новый тег и новые суммы здесь; служба откажется запускать
//! файл, не совпавший с этой таблицей.

use std::fmt::Write;

use sha2::{Digest, Sha256};

use crate::error::{I2pdError, I2pdResult};

/// Версия i2pd.
pub const VERSION: &str = "3.0.0";

/// Тег релиза с поставками i2pd в репозитории Penguin.
pub const TAG: &str = "i2pd-3.0.0";

/// Поставка под одну систему.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Build {
    /// `std::env::consts::OS`.
    pub os: &'static str,
    /// `std::env::consts::ARCH`.
    pub arch: &'static str,
    /// Имя файла в релизе.
    pub asset: &'static str,
    /// SHA-256 файла, шестнадцатеричной строкой.
    pub sha256: &'static str,
}

/// Поставки релиза [`TAG`].
const BUILDS: &[Build] = &[];

impl Build {
    /// Поставка для этой системы.
    pub fn current() -> I2pdResult<Self> {
        Self::of(std::env::consts::OS, std::env::consts::ARCH)
    }

    /// Поставка по именам `std::env::consts`.
    pub fn of(os: &str, arch: &str) -> I2pdResult<Self> {
        BUILDS
            .iter()
            .find(|build| build.os == os && build.arch == arch)
            .copied()
            .ok_or(I2pdError::UnsupportedTarget)
    }

    /// Совпадает ли файл с закреплённой суммой.
    pub fn verify(&self, bytes: &[u8]) -> I2pdResult<()> {
        let actual = sha256_hex(bytes);
        if actual != self.sha256 {
            return Err(I2pdError::ChecksumMismatch {
                expected: self.sha256,
                actual,
            });
        }
        Ok(())
    }
}

/// Имя исполняемого файла у службы.
pub fn file_name() -> &'static str {
    if cfg!(windows) { "i2pd.exe" } else { "i2pd" }
}

/// SHA-256 в нижнем регистре.
fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pinned_sum_is_sha256_hex() {
        for build in BUILDS {
            assert_eq!(build.sha256.len(), 64, "{}", build.asset);
            assert!(
                build
                    .sha256
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                "{}",
                build.asset
            );
        }
    }

    #[test]
    fn a_system_without_a_build_is_named() {
        assert!(matches!(
            Build::of("freebsd", "x86_64"),
            Err(I2pdError::UnsupportedTarget)
        ));
    }

    #[test]
    fn a_changed_file_is_refused() {
        // `printf abc | sha256sum`
        let build = Build {
            os: "test",
            arch: "test",
            asset: "i2pd-test",
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        };
        build.verify(b"abc").expect("тот же файл");
        assert!(matches!(
            build.verify(b"abd"),
            Err(I2pdError::ChecksumMismatch { .. })
        ));
    }
}
