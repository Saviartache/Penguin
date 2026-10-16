//! macOS: регистрация, загрузка и исполнение — отдельные состояния launchd.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::stage::at;
use super::{ServiceStatus, launchd, stage};
use crate::command;
use crate::error::{PlatformError, PlatformResult};
use launchd::{HELPER_DIR, HELPER_PATH, PLIST, PLIST_PATH, TARGET};

const LAUNCHCTL: &str = "/bin/launchctl";

/// Пока снимается прежнее задание с тем же именем, `bootstrap` отказывает — помогает только ожидание.
const BOOTSTRAP_ATTEMPTS: u32 = 20;
const BOOTSTRAP_PAUSE: Duration = Duration::from_millis(500);

/// Кладёт копию программы и регистрирует задание, не запуская; повторный вызов перезаписывает
/// описание и копию на месте, ничего не снимая заранее.
pub fn install(executable: &Path) -> PlatformResult<()> {
    use std::os::unix::fs::PermissionsExt;

    stage::stage(executable, HELPER_DIR, HELPER_PATH)?;
    let plist = Path::new(PLIST_PATH);
    std::fs::write(plist, PLIST).map_err(|err| at(plist, &err))?;
    std::fs::set_permissions(plist, std::fs::Permissions::from_mode(0o644))
        .map_err(|err| at(plist, &err))
}

/// Останавливает задание и удаляет описание; настоящие ошибки остановки фатальны.
pub fn uninstall() -> PlatformResult<()> {
    stop()?;
    if Path::new(PLIST_PATH).try_exists()? {
        std::fs::remove_file(PLIST_PATH)?;
    }
    match std::fs::remove_dir_all(HELPER_DIR) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Включает и запускает задание, не трогая работающий экземпляр.
pub fn start() -> PlatformResult<()> {
    if !Path::new(PLIST_PATH).try_exists()? {
        return Err(PlatformError::Service("service is not installed".into()));
    }
    // Запрет переживает задание и перезагрузку: без `enable` bootstrap проходит, а задание не бежит.
    run(&["enable", TARGET])?;
    if report()?.is_none() {
        bootstrap()?;
    }
    run(&["kickstart", TARGET])
}

/// Выгружает задание штатно; игнорируется только отсутствие.
pub fn stop() -> PlatformResult<()> {
    match command::run(LAUNCHCTL, &["bootout", TARGET]) {
        Ok(_) => Ok(()),
        // Отсутствие домена — не отсутствие службы.
        Err(err) if launchd::absent(err.code()) => run(&["print", "system"]),
        Err(err) => Err(err.into_error(PlatformError::Service, "stopping service")),
    }
}

/// Состояние задания; отказ менеджера или прав не скрывается.
pub fn status() -> PlatformResult<ServiceStatus> {
    if !Path::new(PLIST_PATH).try_exists()? {
        return Ok(ServiceStatus::NotInstalled);
    }
    match report()? {
        Some(report) => launchd::state_from(&report),
        None => Ok(ServiceStatus::Stopped),
    }
}

/// Зарегистрированный файл, если задание имеет роль службы.
pub fn registered_executable() -> PlatformResult<Option<PathBuf>> {
    match std::fs::read_to_string(PLIST_PATH) {
        Ok(text) => Ok(launchd::executable_from(&text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Та ли сборка зарегистрирована, что задаёт вопрос; прежнее описание тоже повод переставить.
pub(super) fn runs_current_build() -> bool {
    std::fs::read_to_string(PLIST_PATH).is_ok_and(|text| text == PLIST)
        && stage::runs_current_build(Some(Path::new(HELPER_PATH)), HELPER_PATH)
}

/// Загружает задание, пережидая отказы launchd.
fn bootstrap() -> PlatformResult<()> {
    let mut attempt = 1;
    loop {
        match command::run(LAUNCHCTL, &["bootstrap", "system", PLIST_PATH]) {
            Ok(_) => return Ok(()),
            Err(err) if attempt >= BOOTSTRAP_ATTEMPTS => {
                return Err(err.into_error(PlatformError::Service, "loading service"));
            }
            Err(_) => {
                attempt += 1;
                std::thread::sleep(BOOTSTRAP_PAUSE);
            }
        }
    }
}

fn report() -> PlatformResult<Option<String>> {
    match command::run(LAUNCHCTL, &["print", TARGET]) {
        Ok(report) => Ok(Some(report)),
        Err(err) if launchd::absent(err.code()) => {
            run(&["print", "system"])?;
            Ok(None)
        }
        Err(err) => Err(err.into_error(PlatformError::Service, "querying service")),
    }
}

fn run(arguments: &[&str]) -> PlatformResult<()> {
    command::run(LAUNCHCTL, arguments)
        .map(|_| ())
        .map_err(|err| err.into_error(PlatformError::Service, "service management"))
}
