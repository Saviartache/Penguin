//! Одно окно на сеанс пользователя.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use penguin_platform::instance::{Instance, InstanceLock};

/// Сколько окно после обновления ждёт, пока прежнее закроется.
const RESTART_WAIT: Duration = Duration::from_secs(15);

/// Занимает место окна; `None` — окно уже открыто. Держать до выхода.
pub(crate) fn lock_window() -> Result<Option<InstanceLock>> {
    let dir = lock_dir()?;
    if std::env::var_os(penguin_gui::RESTARTED).is_some() {
        return InstanceLock::acquire(Instance::Gui, &dir, RESTART_WAIT)
            .map(Some)
            .context("прежнее окно не закрылось после обновления");
    }
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
