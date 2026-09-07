//! Linux: installation and lifecycle of the systemd service.

use std::path::{Path, PathBuf};

use super::{ServiceStatus, stage, systemd};
use crate::command;
use crate::error::{PlatformError, PlatformResult};
use systemd::{HELPER_DIR, HELPER_PATH};

const SYSTEMCTL: &str = "systemctl";
const UNIT: &str = "penguin.service";
const UNIT_PATH: &str = "/etc/systemd/system/penguin.service";

/// Stages the program, registers and enables the service without starting it.
///
/// Repeating it is how a wrong or outdated registration is repaired: the unit
/// and the staged copy are both overwritten in place, and nothing is removed
/// first.
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

/// Где лежит программа, возвращающая файлу предписанный контекст SELinux.
///
/// Два пути, потому что на одних системах `/sbin` — сам каталог, на других
/// ссылка на `/usr/sbin`, и полагаться на `PATH` у службы нельзя.
const RESTORECON: [&str; 2] = ["/sbin/restorecon", "/usr/sbin/restorecon"];

/// Возвращает файлу тот контекст SELinux, который предписывает политика.
///
/// Созданный нами файл получает контекст не от политики, а от каталога и от
/// процесса, который его создал. Там, где SELinux включён — Fedora, RHEL,
/// CentOS и родня, — это значит юнит, который systemd видит не тем, что он
/// есть, и программу, запускаемую не в том домене. Наружу это выходит потоком
/// записей в журнале аудита, и человек читает его вместо работы.
///
/// Необязательно и молча: `restorecon` есть только там, где есть SELinux, и
/// его отсутствие — не отказ, а другая система. Неудача — тоже не отказ:
/// служба ставится и без правильной метки, просто шумит.
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
        tracing::warn!(path, reason = err.reason(), "контекст SELinux не восстановлен");
    }
}

/// Whether the registered unit is the very build asking the question.
pub(super) fn runs_current_build() -> bool {
    let registered = registered_executable().ok().flatten();
    stage::runs_current_build(registered.as_deref(), HELPER_PATH)
}

/// Stops the service and removes its registration, preserving real stop errors.
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

/// Starts the service; starting an already running service is harmless.
pub fn start() -> PlatformResult<()> {
    run(&["start", UNIT])
}

/// Stops the service gracefully. Only an absent, inactive unit is ignored.
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

/// Queries service state, returning manager failures instead of "stopped".
pub fn status() -> PlatformResult<ServiceStatus> {
    if !Path::new(UNIT_PATH).try_exists()? {
        return Ok(ServiceStatus::NotInstalled);
    }
    // Unlike is-active, show succeeds for stopped and transitioning units.
    let answer = command::run(SYSTEMCTL, &["show", "--property=ActiveState", UNIT])
        .map_err(|err| err.into_error(PlatformError::Service, "querying service"))?;
    systemd::state_from(&answer)
}

/// Returns the registered executable, or None for an absent/stale definition.
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
