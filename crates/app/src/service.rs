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
    // Читающая команда не ждёт очереди.
    let _serial = if matches!(command, ServiceCommand::Status) {
        None
    } else {
        Some(penguin_daemon::instance::lock_service_commands()?)
    };
    let access_changed = if prepares_service(command) {
        penguin_daemon::prepare_service(controller_uid, import_config)?
    } else {
        false
    };
    dispatch(command, access_changed, controller_uid)
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

fn dispatch(
    command: &ServiceCommand,
    access_changed: bool,
    controller_uid: Option<u32>,
) -> Result<()> {
    match command {
        ServiceCommand::Ensure => ensure(access_changed, controller_uid),
        ServiceCommand::Install => {
            penguin_daemon::install()?;
            allow_user_start(controller_uid)
        }
        ServiceCommand::Uninstall => penguin_daemon::uninstall(),
        ServiceCommand::Restart => {
            allow_user_start(controller_uid)?;
            restart()
        }
        ServiceCommand::Start => {
            allow_user_start(controller_uid)?;
            start(access_changed)
        }
        ServiceCommand::Stop => service::stop().context("could not stop service"),
        ServiceCommand::Status => penguin_daemon::status(),
    }
}

/// The desktop user starts the service later without a password prompt.
fn allow_user_start(controller_uid: Option<u32>) -> Result<()> {
    service::user_start::allow(controller_uid)
        .context("could not allow the desktop user to start the service")
}

fn ensure(access_changed: bool, controller_uid: Option<u32>) -> Result<()> {
    let status = service::status().context("could not query service state")?;
    // Repair by rewriting, never remove first: a half-done reinstall leaves no service.
    let registered = status != ServiceStatus::NotInstalled && service::registered_verbatim();
    if !registered {
        penguin_daemon::install()?;
    }
    allow_user_start(controller_uid)?;
    if status == ServiceStatus::Running {
        // New registration or controller needs a restart; else give it time to initialize.
        if !registered || access_changed || penguin_daemon::wait_until_ready().is_err() {
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
    // SCM rejects stop on an already stopped service.
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
