//! macOS: registration, loading and execution are separate launchd states.

use std::path::{Path, PathBuf};

use super::{ServiceStatus, launchd};
use crate::command;
use crate::error::{PlatformError, PlatformResult};
use launchd::{PLIST_PATH, TARGET};

const LAUNCHCTL: &str = "/bin/launchctl";

/// Registers the service without launching it before configuration is ready.
pub fn install(executable: &Path) -> PlatformResult<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(PLIST_PATH, launchd::plist(executable)?)?;
    std::fs::set_permissions(PLIST_PATH, std::fs::Permissions::from_mode(0o644))?;
    Ok(())
}

/// Stops the job before removing its definition. Real stop failures are fatal.
pub fn uninstall() -> PlatformResult<()> {
    stop()?;
    if Path::new(PLIST_PATH).try_exists()? {
        std::fs::remove_file(PLIST_PATH)?;
    }
    Ok(())
}

/// Enables and starts the job without killing an already running instance.
pub fn start() -> PlatformResult<()> {
    if !Path::new(PLIST_PATH).try_exists()? {
        return Err(PlatformError::Service("service is not installed".into()));
    }
    for arguments in launchd::start_commands(report()?.is_some()) {
        run(&arguments)?;
    }
    Ok(())
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

/// Returns the executable only when the persisted job has the service role.
pub fn registered_executable() -> PlatformResult<Option<PathBuf>> {
    match std::fs::read_to_string(PLIST_PATH) {
        Ok(text) => Ok(launchd::executable_from(&text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn run(arguments: &[&str]) -> PlatformResult<()> {
    command::run(LAUNCHCTL, arguments)
        .map(|_| ())
        .map_err(|err| err.into_error(PlatformError::Service, "service management"))
}
