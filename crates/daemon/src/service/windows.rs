//! Точка входа службы Windows и обработка управляющих команд.
//!
//! Диспетчер снимает службу, не сообщившую о запуске вовремя, поэтому сначала
//! регистрация обработчика и `Running`, потом остальная работа.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::runtime;

/// Каталог настроек; глобальный, т.к. точку входа вызывает диспетчер.
static CONFIG_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Запускает демона как службу.
pub fn run(config_dir: Option<PathBuf>) -> Result<()> {
    let _ = CONFIG_DIR.set(config_dir);

    service_dispatcher::start(penguin_platform::service::SERVICE_NAME, ffi_service_main)
        .context("не удалось подключиться к диспетчеру служб")
}

/// Точка входа службы.
fn service_main(_arguments: Vec<OsString>) {
    if let Err(err) = serve() {
        tracing::error!(%err, "служба завершилась с ошибкой");
    }
}

/// Обслуживает службу от запуска до остановки.
fn serve() -> Result<()> {
    let config_dir = CONFIG_DIR.get().cloned().flatten();

    let store = runtime::open_store(config_dir.clone())?;
    crate::logging::init_file(store.paths().data_dir(), false);

    let cancel = CancellationToken::new();

    // Первым: иначе диспетчер не сможет остановить службу
    let handler = {
        let cancel = cancel.clone();
        move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                tracing::info!("получена команда остановки");
                cancel.cancel();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle =
        service_control_handler::register(penguin_platform::service::SERVICE_NAME, handler)
            .context("не удалось зарегистрировать обработчик службы")?;

    let report = |state: ServiceState, accept: ServiceControlAccept| {
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });
    };

    // До подъёма движка: он может занять секунды
    report(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    );
    tracing::info!("служба запущена");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("не удалось создать среду выполнения")?;

    let result = runtime.block_on(runtime::run(config_dir, cancel));

    // Всегда, иначе службу нельзя запустить заново
    report(ServiceState::Stopped, ServiceControlAccept::empty());
    tracing::info!("служба остановлена");

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_dir_is_settable_once() {
        let _ = CONFIG_DIR.set(Some(PathBuf::from("C:/penguin")));
        assert!(CONFIG_DIR.get().is_some());
    }

    #[test]
    fn service_name_matches_the_installer() {
        assert_eq!(penguin_platform::service::SERVICE_NAME, "PenguinVpn");
    }
}
