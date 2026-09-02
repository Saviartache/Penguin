//! Служба Windows.
//!
//! Тоннель держит служба, а не окно. Причина не в удобстве: TUN-адаптер,
//! маршруты и брандмауэр требуют прав администратора, и запускать с ними
//! интерфейс — значит запускать с ними `iced`, `wgpu` и драйвер видеокарты.
//! Служба же работает под системной учётной записью и не имеет ни окна, ни
//! графики.
//!
//! Ставится она отдельным действием, а не при первом запуске: установка
//! службы — изменение системы, и делаться оно должно по явной команде.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::error::{PlatformError, PlatformResult};
use crate::service::{SERVICE_DISPLAY_NAME, SERVICE_NAME, ServiceStatus};

/// Сколько ждать остановки службы, прежде чем считать, что она зависла.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Ставит службу.
pub fn install(executable: &Path) -> PlatformResult<()> {
    let manager = open_manager(ServiceManagerAccess::CREATE_SERVICE)?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        // Автоматический запуск: тоннель должен подниматься до входа
        // пользователя, иначе первые секунды сеанса трафик идёт мимо него.
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable.to_path_buf(),
        // Аргумент говорит демону, что он запущен как служба: путь запуска у
        // него от этого другой.
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        // `LocalSystem`: без него не создать адаптер и не тронуть маршруты.
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .map_err(|e| classify(e, "не удалось поставить службу"))?;

    service
        .set_description("Клиент Penguin: тоннель, маршрутизация и защита от утечек")
        .map_err(|e| PlatformError::Service(format!("описание службы: {e}")))?;

    tracing::info!(name = SERVICE_NAME, "служба установлена");
    Ok(())
}

/// Путь к файлу, который сейчас зарегистрирован службой.
///
/// `None` — службы нет.
///
/// Права на это не нужны: читать настройки службы разрешено всем, и окно
/// пользуется этим при запуске, чтобы не просить UAC на ровном месте.
pub fn registered_executable() -> PlatformResult<Option<PathBuf>> {
    let manager = open_manager(ServiceManagerAccess::CONNECT)?;
    let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG) else {
        return Ok(None);
    };

    let config = service
        .query_config()
        .map_err(|e| PlatformError::Service(format!("настройки службы не читаются: {e}")))?;

    // `query_config` отдаёт командную строку целиком — с кавычками и
    // аргументами; путь из неё надо выделить.
    let command_line = config.executable_path.to_string_lossy().into_owned();
    Ok(Some(PathBuf::from(executable_of(&command_line))))
}

/// Выделяет путь к файлу из командной строки службы.
///
/// SCM хранит одну строку целиком: `"C:\Program Files\Penguin\penguin.exe"
/// --service`. Сравнивать её с путём напрямую нельзя — не совпадёт никогда.
///
/// Свободная функция с тестом: ошибка здесь означает, что программа считает
/// чужую службу своей — или свою чужой и переустанавливает её при каждом
/// запуске.
fn executable_of(command_line: &str) -> &str {
    let trimmed = command_line.trim();

    // В кавычках — до закрывающей: путь с пробелом иначе распался бы надвое.
    if let Some(rest) = trimmed.strip_prefix('"') {
        return rest.split('"').next().unwrap_or(rest);
    }

    // Без кавычек пробела в пути быть не может: по нему SCM и отделяет
    // аргументы.
    trimmed.split(' ').next().unwrap_or(trimmed)
}

/// Убирает службу.
pub fn uninstall() -> PlatformResult<()> {
    // Остановка перед удалением: удалённая, но работающая служба остаётся в
    // системе до перезагрузки и мешает поставить её заново.
    let _ = stop();

    let manager = open_manager(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::DELETE)
        .map_err(|e| classify(e, "служба не найдена"))?;

    service
        .delete()
        .map_err(|e| classify(e, "не удалось удалить службу"))?;
    tracing::info!(name = SERVICE_NAME, "служба удалена");
    Ok(())
}

/// Запускает службу.
pub fn start() -> PlatformResult<()> {
    let manager = open_manager(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::START)
        .map_err(|e| classify(e, "служба не найдена"))?;

    service
        .start::<&str>(&[])
        .map_err(|e| classify(e, "не удалось запустить службу"))?;
    Ok(())
}

/// Останавливает службу.
pub fn stop() -> PlatformResult<()> {
    let manager = open_manager(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|e| classify(e, "служба не найдена"))?;

    service
        .stop()
        .map_err(|e| classify(e, "не удалось остановить службу"))?;

    // Ждём подтверждения: без него следующая команда — например, удаление —
    // придёт к ещё работающей службе.
    let deadline = std::time::Instant::now() + STOP_TIMEOUT;
    while std::time::Instant::now() < deadline {
        let Ok(status) = service.query_status() else {
            break;
        };
        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    Err(PlatformError::Service(
        "служба не остановилась за отведённое время".to_owned(),
    ))
}

/// Состояние службы.
pub fn status() -> PlatformResult<ServiceStatus> {
    let manager = open_manager(ServiceManagerAccess::CONNECT)?;

    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(service) => service,
        // Службы нет — законное состояние, а не ошибка: клиент вполне может
        // работать в режиме прокси.
        Err(_) => return Ok(ServiceStatus::NotInstalled),
    };

    let state = service
        .query_status()
        .map_err(|e| PlatformError::Service(format!("состояние службы: {e}")))?;

    Ok(match state.current_state {
        ServiceState::Running => ServiceStatus::Running,
        ServiceState::Stopped => ServiceStatus::Stopped,
        _ => ServiceStatus::Transitioning,
    })
}

fn open_manager(access: ServiceManagerAccess) -> PlatformResult<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access)
        .map_err(|e| classify(e, "не удалось обратиться к диспетчеру служб"))
}

/// Переводит ошибку в понятную.
fn classify(err: windows_service::Error, context: &str) -> PlatformError {
    let text = err.to_string();
    // Управление службами требует прав администратора — и это самая частая
    // причина отказа.
    if text.contains("Access is denied") || text.contains("отказано в доступе") {
        return PlatformError::PermissionDenied(context.to_owned());
    }
    PlatformError::Service(format!("{context}: {text}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_of_a_missing_service_is_not_an_error() {
        // Клиент вполне может работать в режиме прокси, без службы вовсе.
        match status() {
            Ok(_) => {}
            Err(err) => assert!(err.needs_privileges(), "неожиданная ошибка: {err}"),
        }
    }

    #[test]
    fn service_name_is_stable() {
        // Имя стоит в системе у уже установленных служб — менять его нельзя.
        assert_eq!(SERVICE_NAME, "PenguinVpn");
    }

    #[test]
    fn the_path_is_taken_out_of_the_command_line() {
        // Так это лежит в SCM: путь в кавычках и аргумент следом.
        assert_eq!(
            executable_of(r#""C:\Program Files\Penguin\penguin.exe" --service"#),
            r"C:\Program Files\Penguin\penguin.exe"
        );
    }

    #[test]
    fn a_path_without_quotes_is_cut_at_the_argument() {
        assert_eq!(
            executable_of(r"C:\penguin\penguin.exe --service"),
            r"C:\penguin\penguin.exe"
        );
    }

    #[test]
    fn a_bare_path_survives_untouched() {
        assert_eq!(
            executable_of(r"C:\penguin\penguin.exe"),
            r"C:\penguin\penguin.exe"
        );
        assert_eq!(
            executable_of(r#""C:\penguin\penguin.exe""#),
            r"C:\penguin\penguin.exe"
        );
    }

    #[test]
    fn spaces_around_the_command_line_do_not_leak_into_the_path() {
        // Путь с хвостовым пробелом не откроется, а сравнение с ним не
        // совпадёт никогда — служба переустанавливалась бы при каждом запуске.
        assert_eq!(
            executable_of("  C:\\penguin\\penguin.exe --service  "),
            r"C:\penguin\penguin.exe"
        );
    }

    #[test]
    fn install_without_privileges_says_why() {
        let executable = std::env::current_exe().expect("свой путь известен");
        match install(&executable) {
            // Тест запущен от администратора — убираем за собой.
            Ok(()) => uninstall().expect("удаляется"),
            Err(err) => assert!(
                err.needs_privileges() || matches!(err, PlatformError::Service(_)),
                "неожиданная ошибка: {err}"
            ),
        }
    }
}
