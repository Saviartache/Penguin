//! macOS: registration, loading and execution are separate launchd states.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::stage::at;
use super::{ServiceStatus, launchd, stage};
use crate::command;
use crate::error::{PlatformError, PlatformResult};
use launchd::{HELPER_DIR, HELPER_PATH, PLIST, PLIST_PATH, TARGET};

const LAUNCHCTL: &str = "/bin/launchctl";

/// How long to keep asking launchd to load the job.
///
/// While the previous job of the same name is being torn down, `bootstrap`
/// answers with a refusal and nothing but waiting helps. Fractions of a
/// second in practice; the shipped clients wait the same way.
const BOOTSTRAP_ATTEMPTS: u32 = 20;
const BOOTSTRAP_PAUSE: Duration = Duration::from_millis(500);

/// Stages the program and registers the job without launching it.
///
/// Repeating it is how a wrong or outdated registration is repaired: the job
/// definition and the staged copy are both overwritten in place. Nothing is
/// removed first, so a registration that cannot be written leaves the machine
/// with the service it already had.
pub fn install(executable: &Path) -> PlatformResult<()> {
    use std::os::unix::fs::PermissionsExt;

    stage::stage(executable, HELPER_DIR, HELPER_PATH)?;
    let plist = Path::new(PLIST_PATH);
    std::fs::write(plist, PLIST).map_err(|err| at(plist, &err))?;
    std::fs::set_permissions(plist, std::fs::Permissions::from_mode(0o644))
        .map_err(|err| at(plist, &err))
}

/// Stops the job before removing its definition. Real stop failures are fatal.
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

/// Enables and starts the job without killing an already running instance.
pub fn start() -> PlatformResult<()> {
    if !Path::new(PLIST_PATH).try_exists()? {
        return Err(PlatformError::Service("service is not installed".into()));
    }
    // A ban outlives both the job and a reboot: without lifting it first the
    // bootstrap succeeds and the job still never runs.
    run(&["enable", TARGET])?;
    if report()?.is_none() {
        bootstrap()?;
    }
    run(&["kickstart", TARGET])
}

/// Unloads the job with launchd's graceful termination, ignoring only absence.
pub fn stop() -> PlatformResult<()> {
    match command::run(LAUNCHCTL, &["bootout", TARGET]) {
        Ok(_) => Ok(()),
        // A missing manager/domain must not be mistaken for a missing service.
        Err(err) if launchd::absent(err.code()) => run(&["print", "system"]),
        Err(err) => Err(err.into_error(PlatformError::Service, "stopping service")),
    }
}

/// Queries the job state without hiding manager/permission failures.
pub fn status() -> PlatformResult<ServiceStatus> {
    if !Path::new(PLIST_PATH).try_exists()? {
        return Ok(ServiceStatus::NotInstalled);
    }
    match report()? {
        Some(report) => launchd::state_from(&report),
        None => Ok(ServiceStatus::Stopped),
    }
}

/// Returns the executable only when the persisted job has the service role.
pub fn registered_executable() -> PlatformResult<Option<PathBuf>> {
    match std::fs::read_to_string(PLIST_PATH) {
        Ok(text) => Ok(launchd::executable_from(&text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Whether the registered job is the very build asking the question.
pub(super) fn runs_current_build() -> bool {
    let registered = registered_executable().ok().flatten();
    stage::runs_current_build(registered.as_deref(), HELPER_PATH)
}

/// Loads the job, sitting out launchd's refusals.
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
