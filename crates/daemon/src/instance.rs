//! Единственность демона и команд службы.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use penguin_config::Paths;
use penguin_platform::instance::{Instance, InstanceLock};

/// Сколько новый демон ждёт старого, который ещё завершается при перезапуске.
const DAEMON_WAIT: Duration = Duration::from_secs(5);

/// Команды службы ждут друг друга долго: установка и запуск занимают секунды.
const COMMANDS_WAIT: Duration = Duration::from_secs(60);

/// Занимает место единственного демона; держать до выхода.
pub fn lock_daemon() -> Result<InstanceLock> {
    acquire(Instance::Daemon, DAEMON_WAIT)
}

/// Не даёт двум командам `service ...` менять установку одновременно; ждёт очереди.
pub fn lock_service_commands() -> Result<InstanceLock> {
    acquire(Instance::ServiceCommands, COMMANDS_WAIT)
}

fn acquire(instance: Instance, wait: Duration) -> Result<InstanceLock> {
    let dir = lock_dir()?;
    InstanceLock::acquire(instance, &dir, wait)
        .with_context(|| format!("не удалось занять блокировку: {}", instance.label()))
}

/// Под root — общий каталог данных, иначе свой: у пользовательского запуска свой сокет.
fn lock_dir() -> Result<PathBuf> {
    let paths = if penguin_platform::is_elevated() {
        Paths::machine()
    } else {
        Paths::user().ok()
    }
    .context("каталог блокировок недоступен")?;
    Ok(paths.data_dir().to_owned())
}
