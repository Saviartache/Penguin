//! Linux: installation and lifecycle of the systemd service.

use std::path::{Path, PathBuf};

use super::{ServiceStatus, systemd};
use crate::command;
use crate::error::{PlatformError, PlatformResult};

const SYSTEMCTL: &str = "systemctl";
const UNIT: &str = "penguin.service";
const UNIT_PATH: &str = "/etc/systemd/system/penguin.service";

/// Registers and enables the service without starting it.
pub fn install(executable: &Path) -> PlatformResult<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(UNIT_PATH, systemd::unit(executable)?)?;
    std::fs::set_permissions(UNIT_PATH, std::fs::Permissions::from_mode(0o644))?;
    run(&["daemon-reload"])?;
    run(&["enable", UNIT])
}

/// Stops the service and removes its registration, preserving real stop errors.
pub fn uninstall() -> PlatformResult<()> {
    stop()?;
    if Path::new(UNIT_PATH).try_exists()? {
        run(&["disable", UNIT])?;
        std::fs::remove_file(UNIT_PATH)?;
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
