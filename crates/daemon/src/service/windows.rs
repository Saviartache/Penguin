//! Точка входа службы Windows и обработка управляющих команд.
//!
//! Диспетчер служб устроен строго: он вызывает точку входа в своём потоке,
//! ждёт, что она немедленно зарегистрирует обработчик команд, и с этого
//! момента считает службу обязанной отвечать. Служба, не сообщившая о
//! запуске за отведённое время, снимается принудительно.
//!
//! Отсюда порядок: сначала регистрация и `Running`, потом вся настоящая
//! работа. Поднимать движок до регистрации нельзя — на медленной машине это
//! секунды, и диспетчер сочтёт службу зависшей.

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

/// Каталог настроек, переданный при запуске.
///
/// Через глобальную переменную, потому что точку входа службы вызывает
/// диспетчер и передать ей аргументы иначе нечем.
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
        // Терминала у службы нет; единственное место, куда можно пожаловаться,
        // — журнал событий и файл журнала.
        tracing::error!(%err, "служба завершилась с ошибкой");
    }
}

/// Обслуживает службу от запуска до остановки.
fn serve() -> Result<()> {
    let config_dir = CONFIG_DIR.get().cloned().flatten();

    let store = runtime::open_store(config_dir.clone())?;
    let _guard = crate::logging::init_file(store.paths().data_dir(), false);

    let cancel = CancellationToken::new();

    // Обработчик регистрируется первым: до этого момента диспетчер не может
    // даже попросить службу остановиться.
    let handler = {
        let cancel = cancel.clone();
        move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                tracing::info!("получена команда остановки");
                cancel.cancel();
                ServiceControlHandlerResult::NoError
            }
            // На проверку состояния положено отвечать успехом, ничего не делая.
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

    // О запуске сообщается до подъёма движка: на медленной машине это
    // секунды, и диспетчер счёл бы службу зависшей.
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

    // Об остановке сообщается в любом случае, включая аварийный выход: иначе
    // диспетчер считает службу работающей и не даёт запустить её заново.
    report(ServiceState::Stopped, ServiceControlAccept::empty());
    tracing::info!("служба остановлена");

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_dir_is_settable_once() {
        // Диспетчер вызывает точку входа один раз за жизнь процесса.
        let _ = CONFIG_DIR.set(Some(PathBuf::from("C:/penguin")));
        assert!(CONFIG_DIR.get().is_some());
    }

    #[test]
    fn service_name_matches_the_installer() {
        // Имя, под которым служба зарегистрирована, и имя, под которым она
        // регистрирует обработчик, обязаны совпадать — иначе диспетчер не
        // свяжет их между собой.
        assert_eq!(penguin_platform::service::SERVICE_NAME, "PenguinVpn");
    }
}
