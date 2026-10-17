//! Одно окно на сеанс пользователя.

use std::path::PathBuf;

use anyhow::{Context, Result};
use penguin_platform::instance::{Instance, InstanceLock};

/// Занимает место окна; `None` — окно уже открыто. Держать до выхода.
pub(crate) fn lock_window() -> Result<Option<InstanceLock>> {
    let dir = lock_dir()?;
    InstanceLock::try_acquire(Instance::Gui, &dir).context("не удалось проверить, открыто ли окно")
}

/// Каталог сеанса, если он есть; иначе данные пользователя.
fn lock_dir() -> Result<PathBuf> {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(runtime));
    }
    let paths = penguin_config::Paths::user().context("каталог данных пользователя недоступен")?;
    Ok(paths.data_dir().to_owned())
}
