//! Какая поставка нужна этой системе. Имена задаёт `.github/workflows/release.yml`.

use crate::version::Version;

/// Формат архива поставки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Windows и macOS.
    Zip,
    /// Linux.
    TarGz,
}

/// Строка матрицы выпуска.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    /// Суффикс в имени архива.
    pub name: &'static str,
    /// Формат.
    pub format: Format,
    /// Путь исполняемого файла внутри архива.
    pub member: &'static str,
}

const WINDOWS_X64: Target = Target {
    name: "windows-x64",
    format: Format::Zip,
    member: "penguin.exe",
};
const LINUX_X64: Target = Target {
    name: "linux-x64",
    format: Format::TarGz,
    member: "penguin",
};
const MACOS_ARM64: Target = Target {
    name: "macos-arm64",
    format: Format::Zip,
    member: "Penguin.app/Contents/MacOS/penguin",
};
const MACOS_X64: Target = Target {
    name: "macos-x64",
    format: Format::Zip,
    member: "Penguin.app/Contents/MacOS/penguin",
};

impl Target {
    /// Поставка для системы, в которой работает программа; `None` — такую не собирают.
    pub fn current() -> Option<Self> {
        Self::of(std::env::consts::OS, std::env::consts::ARCH)
    }

    /// Поставка по именам `std::env::consts`.
    pub fn of(os: &str, arch: &str) -> Option<Self> {
        match (os, arch) {
            ("windows", "x86_64") => Some(WINDOWS_X64),
            ("linux", "x86_64") => Some(LINUX_X64),
            ("macos", "aarch64") => Some(MACOS_ARM64),
            ("macos", "x86_64") => Some(MACOS_X64),
            _ => None,
        }
    }

    /// Имя архива в релизе: `penguin-0.8.0-linux-x64.tar.gz`.
    pub fn archive_name(&self, version: &Version) -> String {
        let extension = match self.format {
            Format::Zip => "zip",
            Format::TarGz => "tar.gz",
        };
        format!("penguin-{version}-{}.{extension}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_release_matrix_row_is_picked_by_its_system() {
        let version: Version = "0.8.0".parse().expect("версия");
        for (os, arch, archive) in [
            ("windows", "x86_64", "penguin-0.8.0-windows-x64.zip"),
            ("linux", "x86_64", "penguin-0.8.0-linux-x64.tar.gz"),
            ("macos", "aarch64", "penguin-0.8.0-macos-arm64.zip"),
            ("macos", "x86_64", "penguin-0.8.0-macos-x64.zip"),
        ] {
            let target = Target::of(os, arch).expect("есть поставка");
            assert_eq!(target.archive_name(&version), archive);
        }
    }

    #[test]
    fn systems_without_a_build_get_none() {
        assert_eq!(Target::of("linux", "aarch64"), None);
        assert_eq!(Target::of("windows", "aarch64"), None);
        assert_eq!(Target::of("freebsd", "x86_64"), None);
    }
}
