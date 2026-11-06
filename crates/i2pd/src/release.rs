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
const BUILDS: &[Build] = &[
    Build {
        os: "windows",
        arch: "x86_64",
        asset: "i2pd-windows-x64.exe",
        sha256: "426d37c191a374357f903491e5114b2ba9b488c66a9eb1177d54e0836eac3b82",
    },
    Build {
        os: "linux",
        arch: "x86_64",
        asset: "i2pd-linux-x64",
        sha256: "c5888ecd7f0217a3df376747b5f6dc95462e52eb4a2aa8ec25f69b1568035337",
    },
    Build {
        os: "macos",
        arch: "aarch64",
        asset: "i2pd-macos-arm64",
        sha256: "1c27765c9d221d221e21fa23b3211fc32be43e03f7d9e3a09258b2ab58d1640e",
    },
    Build {
        os: "macos",
        arch: "x86_64",
        asset: "i2pd-macos-x64",
        sha256: "aca43b45e56ae01b6db335996ded1ee74fe2354a31edb346500108d4648791f7",
    },
];

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
    fn every_penguin_target_has_an_i2pd() {
        for (os, arch) in [
            ("windows", "x86_64"),
            ("linux", "x86_64"),
            ("macos", "aarch64"),
            ("macos", "x86_64"),
        ] {
            assert!(Build::of(os, arch).is_ok(), "{os}-{arch}");
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
