//! i2pd для протокола I2P: закреплённый выпуск в каталог пользователя.
//!
//! Окно зовёт это само (`AGENTS.md` §1.11) и передаёт файл службе: каталог
//! пользователя служба не читает, а запускает только совпавший с суммой.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use penguin_config::Paths;
use penguin_i2pd::Build;
use penguin_i2pd::release::{TAG, VERSION, file_name};
use serde::Serialize;

use crate::output::{Format, emit};

/// Файл ~5–10 МБ; предел с запасом.
const LIMIT: u64 = 64 * 1024 * 1024;

/// Что поставлено.
#[derive(Debug, Serialize)]
struct Installed {
    path: PathBuf,
    version: &'static str,
}

/// Качает i2pd, если его нет или он не тот; печатает путь.
pub fn install(format: Format) -> Result<()> {
    let build = Build::current()?;
    let path = Paths::user()
        .context("каталог данных пользователя неизвестен")?
        .i2pd_dir()
        .join(file_name());

    if !matches_pinned(&build, &path) {
        let bytes = penguin_update::download_release_asset(TAG, build.asset, LIMIT)?;
        build.verify(&bytes)?;
        write(&path, &bytes)?;
    }

    emit(
        format,
        &Installed {
            path,
            version: VERSION,
        },
        |installed| format!("i2pd {} — {}", installed.version, installed.path.display()),
    );
    Ok(())
}

fn matches_pinned(build: &Build, path: &Path) -> bool {
    std::fs::read(path).is_ok_and(|bytes| build.verify(&bytes).is_ok())
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
    }
    std::fs::write(path, bytes).with_context(|| path.display().to_string())
}
