//! Linux: установка и жизненный цикл службы systemd.

use std::path::{Path, PathBuf};

use super::{ServiceStatus, stage, systemd};
use crate::command;
use crate::error::{PlatformError, PlatformResult};
use systemd::{HELPER_DIR, HELPER_PATH};

const SYSTEMCTL: &str = "systemctl";
const UNIT: &str = "penguin.service";
const UNIT_PATH: &str = "/etc/systemd/system/penguin.service";

/// Кладёт копию программы, регистрирует и включает службу, не запуская; повторный вызов
/// перезаписывает юнит и копию на месте, ничего не снимая заранее.
pub fn install(executable: &Path) -> PlatformResult<()> {
    use std::os::unix::fs::PermissionsExt;

    stage::stage(executable, HELPER_DIR, HELPER_PATH)?;
    restore_context(HELPER_DIR, true);

    let unit = Path::new(UNIT_PATH);
    std::fs::write(unit, systemd::UNIT_TEXT).map_err(|err| stage::at(unit, &err))?;
    std::fs::set_permissions(unit, std::fs::Permissions::from_mode(0o644))
        .map_err(|err| stage::at(unit, &err))?;
    restore_context(UNIT_PATH, false);

    run(&["daemon-reload"])?;
    run(&["enable", UNIT])
}

/// Пути `restorecon`: `/sbin` бывает каталогом или ссылкой на `/usr/sbin`, `PATH` у службы нет.
const RESTORECON: [&str; 2] = ["/sbin/restorecon", "/usr/sbin/restorecon"];

/// Возвращает файлу контекст SELinux по политике (иначе поток записей аудита). Молча: без SELinux
/// `restorecon` нет, а неудача не мешает службе.
fn restore_context(path: &str, recursive: bool) {
    let Some(program) = RESTORECON
        .iter()
        .copied()
        .find(|program| Path::new(program).exists())
    else {
        return;
    };
    let mut arguments = vec!["-F"];
    if recursive {
        arguments.push("-R");
    }
    arguments.push(path);

    if let Err(err) = command::run(program, &arguments) {
        tracing::warn!(
            path,
            reason = err.reason(),
            "контекст SELinux не восстановлен"
        );
    }
}

/// Та ли сборка зарегистрирована, что задаёт вопрос.
pub(super) fn runs_current_build() -> bool {
    let registered = registered_executable().ok().flatten();
    stage::runs_current_build(registered.as_deref(), HELPER_PATH)
}

/// Останавливает службу и снимает регистрацию; настоящие ошибки остановки не скрываются.
pub fn uninstall() -> PlatformResult<()> {
    stop()?;
    if Path::new(UNIT_PATH).try_exists()? {
        run(&["disable", UNIT])?;
        std::fs::remove_file(UNIT_PATH)?;
    }
    match std::fs::remove_dir_all(HELPER_DIR) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    run(&["daemon-reload"])
}

/// Запускает службу; запуск работающей безвреден.
pub fn start() -> PlatformResult<()> {
    run(&["start", UNIT])
}

/// Останавливает службу; игнорируется только отсутствующий неактивный юнит.
pub fn stop() -> PlatformResult<()> {
    let report = command::run(
        SYSTEMCTL,
        &["show", "--property=LoadState,ActiveState", UNIT],
    )
    .map_err(|err| err.into_error(PlatformError::Service, "querying service"))?;
    if systemd::absent(&report) {
        return Ok(());
    }
    run(&["stop", UNIT])
}

/// Состояние службы; отказ менеджера возвращается ошибкой, а не «остановлена».
pub fn status() -> PlatformResult<ServiceStatus> {
    if !Path::new(UNIT_PATH).try_exists()? {
        return Ok(ServiceStatus::NotInstalled);
    }
    // В отличие от `is-active`, `show` успешен и для остановленных, и для переходных состояний.
    let answer = command::run(SYSTEMCTL, &["show", "--property=ActiveState", UNIT])
        .map_err(|err| err.into_error(PlatformError::Service, "querying service"))?;
    systemd::state_from(&answer)
}

/// Зарегистрированный файл; `None` — юнита нет или он чужой.
pub fn registered_executable() -> PlatformResult<Option<PathBuf>> {
    match std::fs::read_to_string(UNIT_PATH) {
        Ok(text) => Ok(systemd::executable_from(&text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn run(arguments: &[&str]) -> PlatformResult<()> {
    command::run(SYSTEMCTL, arguments)
        .map(|_| ())
        .map_err(|err| err.into_error(PlatformError::Service, "service management"))
}
