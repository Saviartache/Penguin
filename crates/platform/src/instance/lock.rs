//! Роли процесса и ожидание блокировки.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::error::{PlatformError, PlatformResult};

#[cfg(unix)]
use super::unix as sys;
#[cfg(windows)]
use super::windows as sys;

/// Шаг опроса, пока блокировку держит другой процесс.
const POLL_STEP: Duration = Duration::from_millis(100);

/// Что именно должно быть в одном экземпляре.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instance {
    /// Окно: одно на сеанс пользователя.
    Gui,
    /// Демон (служба и `--foreground`): один на машину.
    Daemon,
    /// Команды `service ...`: меняют установку по одной.
    ServiceCommands,
}

impl Instance {
    /// Имя мьютекса Windows.
    #[cfg(windows)]
    pub(super) const fn mutex_name(self) -> &'static str {
        match self {
            Self::Gui => "Local\\Penguin.Gui",
            Self::Daemon => "Global\\Penguin.Daemon",
            Self::ServiceCommands => "Global\\Penguin.Service",
        }
    }

    /// Имя файла блокировки в каталоге вызывающего.
    #[cfg(unix)]
    pub(super) const fn file_name(self) -> &'static str {
        match self {
            Self::Gui => "gui.lock",
            Self::Daemon => "daemon.lock",
            Self::ServiceCommands => "service.lock",
        }
    }

    /// Название для сообщения об ошибке.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Gui => "окно",
            Self::Daemon => "демон",
            Self::ServiceCommands => "команда службы",
        }
    }
}

/// Захваченная блокировка; снимается, когда значение уничтожено или процесс завершён.
#[derive(Debug)]
pub struct InstanceLock {
    _held: sys::Held,
}

impl InstanceLock {
    /// Пробует занять один раз: `None` — занято другим процессом.
    ///
    /// `dir` — каталог файла блокировки на Unix (создаётся); на Windows не используется.
    pub fn try_acquire(instance: Instance, dir: &Path) -> PlatformResult<Option<Self>> {
        Ok(sys::try_lock(instance, dir)?.map(|held| Self { _held: held }))
    }

    /// Ждёт блокировку не дольше `timeout`; занято дольше — [`PlatformError::AlreadyRunning`].
    pub fn acquire(instance: Instance, dir: &Path, timeout: Duration) -> PlatformResult<Self> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(lock) = Self::try_acquire(instance, dir)? {
                return Ok(lock);
            }
            if Instant::now() >= deadline {
                return Err(PlatformError::AlreadyRunning(instance.label()));
            }
            std::thread::sleep(POLL_STEP);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn second_grab_fails_until_the_first_is_dropped() {
        let dir = tempfile::tempdir().expect("каталог");
        let first = InstanceLock::try_acquire(Instance::Gui, dir.path())
            .expect("захват")
            .expect("свободно");

        assert!(
            InstanceLock::try_acquire(Instance::Gui, dir.path())
                .expect("захват")
                .is_none()
        );
        // Роли независимы.
        assert!(
            InstanceLock::try_acquire(Instance::Daemon, dir.path())
                .expect("захват")
                .is_some()
        );

        drop(first);
        assert!(
            InstanceLock::try_acquire(Instance::Gui, dir.path())
                .expect("захват")
                .is_some()
        );
    }

    #[test]
    fn waiting_gives_up_with_a_named_error() {
        let dir = tempfile::tempdir().expect("каталог");
        let _held = InstanceLock::try_acquire(Instance::Daemon, dir.path()).expect("захват");

        let err = InstanceLock::acquire(Instance::Daemon, dir.path(), Duration::from_millis(250))
            .expect_err("занято");
        assert!(matches!(err, PlatformError::AlreadyRunning("демон")));
    }

    #[test]
    fn waiting_succeeds_once_the_holder_lets_go() {
        let dir = tempfile::tempdir().expect("каталог");
        let held = InstanceLock::try_acquire(Instance::Daemon, dir.path()).expect("захват");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            drop(held);
        });

        InstanceLock::acquire(Instance::Daemon, dir.path(), Duration::from_secs(5))
            .expect("дождались");
        releaser.join().expect("поток");
    }
}
