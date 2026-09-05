//! Service orchestration: preparation, registration, start, then IPC readiness.

use std::path::Path;

use anyhow::{Context, Result};
use penguin_platform::service::{self, ServiceStatus};

use crate::args::ServiceCommand;

pub(crate) fn run(
    command: &ServiceCommand,
    controller_uid: Option<u32>,
    import_config: Option<&Path>,
) -> Result<()> {
    let access_changed = if prepares_service(command) {
        penguin_daemon::prepare_service(controller_uid, import_config)?
    } else {
        false
    };
    dispatch(command, access_changed)
}

pub(crate) fn prepares_service(command: &ServiceCommand) -> bool {
    matches!(
        command,
        ServiceCommand::Ensure
            | ServiceCommand::Install
            | ServiceCommand::Start
            | ServiceCommand::Restart
    )
}

fn dispatch(command: &ServiceCommand, access_changed: bool) -> Result<()> {
    match command {
        ServiceCommand::Ensure => ensure(access_changed),
        ServiceCommand::Install => penguin_daemon::install(),
        ServiceCommand::Uninstall => penguin_daemon::uninstall(),
        ServiceCommand::Restart => restart(),
        ServiceCommand::Start => start(access_changed),
        ServiceCommand::Stop => service::stop().context("could not stop service"),
        ServiceCommand::Status => penguin_daemon::status(),
    }
}

fn ensure(access_changed: bool) -> Result<()> {
    let mut status = service::status().context("could not query service state")?;
    if status != ServiceStatus::NotInstalled && !service::registered_verbatim() {
        penguin_daemon::uninstall()?;
        status = ServiceStatus::NotInstalled;
    }
    if status == ServiceStatus::NotInstalled {
        penguin_daemon::install()?;
        // Registration does not launch the daemon on any platform.
        status = ServiceStatus::Stopped;
    }
    if status == ServiceStatus::Running {
        // A running process can still be initializing. Give it time before
        // attempting repair; a changed controller needs new socket ownership.
        if access_changed || penguin_daemon::wait_until_ready().is_err() {
            return restart();
        }
    } else {
        service::start().context("could not start service")?;
        penguin_daemon::wait_until_ready()?;
    }
    println!("Service is ready.");
    Ok(())
}

fn start(access_changed: bool) -> Result<()> {
    if service::status()? == ServiceStatus::Running {
        if access_changed {
            return restart();
        }
    } else {
        service::start().context("could not start service")?;
    }
    penguin_daemon::wait_until_ready()
}

fn restart() -> Result<()> {
    // Unix stop ignores only absence. On Windows skip an already stopped
    // service, since SCM rejects another stop control in that state.
    if service::status()? != ServiceStatus::Stopped {
        service::stop().context("could not stop service before restart")?;
    }
    service::start().context("could not restart service")?;
    penguin_daemon::wait_until_ready()?;
    println!("Service restarted and ready.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_commands_that_can_launch_prepare_configuration_and_access() {
        for command in [
            ServiceCommand::Ensure,
            ServiceCommand::Install,
            ServiceCommand::Start,
            ServiceCommand::Restart,
        ] {
            assert!(prepares_service(&command));
        }
        for command in [
            ServiceCommand::Stop,
            ServiceCommand::Uninstall,
            ServiceCommand::Status,
        ] {
            assert!(!prepares_service(&command));
        }
    }
}
