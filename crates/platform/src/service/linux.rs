//! Linux: служба systemd.
//!
//! Демонизировать себя не нужно и вредно: systemd сам держит службу и сам
//! читает её журнал из стандартного потока. От нас требуется только файл с
//! описанием и три команды.

use std::path::{Path, PathBuf};

use crate::command;
use crate::error::{PlatformError, PlatformResult};
use crate::service::ServiceStatus;

/// Программа управления службами.
const SYSTEMCTL: &str = "systemctl";

/// Имя службы в systemd.
const UNIT: &str = "penguin.service";

/// Где лежит описание службы.
const UNIT_PATH: &str = "/etc/systemd/system/penguin.service";

/// Права файла описания.
///
/// Описание задаёт программу, которая работает с правами системы: доступное
/// на запись кому попало, оно и есть способ эти права получить.
const UNIT_MODE: u32 = 0o644;

/// Ставит службу.
pub fn install(executable: &Path) -> PlatformResult<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(UNIT_PATH, unit(executable))
        .map_err(|err| PlatformError::Service(format!("{UNIT_PATH}: {err}")))?;
    std::fs::set_permissions(UNIT_PATH, std::fs::Permissions::from_mode(UNIT_MODE))
        .map_err(|err| PlatformError::Service(format!("{UNIT_PATH}: {err}")))?;

    // Без перечитывания systemd не увидит нового файла и ответит «нет такой
    // службы» на первую же команду.
    run(&["daemon-reload"])?;
    run(&["enable", UNIT])?;
    Ok(())
}

/// Убирает службу.
pub fn uninstall() -> PlatformResult<()> {
    // Остановка и снятие с автозапуска могут не удаться потому, что службы и
    // так нет; файл убрать это не мешает.
    if let Err(err) = run(&["disable", "--now", UNIT]) {
        tracing::debug!(%err, "снимать с автозапуска было нечего");
    }
    if Path::new(UNIT_PATH).exists() {
        std::fs::remove_file(UNIT_PATH)
            .map_err(|err| PlatformError::Service(format!("{UNIT_PATH}: {err}")))?;
    }
    run(&["daemon-reload"])?;
    Ok(())
}

/// Запускает службу.
pub fn start() -> PlatformResult<()> {
    run(&["start", UNIT])
}

/// Останавливает службу.
pub fn stop() -> PlatformResult<()> {
    run(&["stop", UNIT])
}

/// Состояние службы.
pub fn status() -> PlatformResult<ServiceStatus> {
    if !Path::new(UNIT_PATH).exists() {
        return Ok(ServiceStatus::NotInstalled);
    }

    // `is-active` возвращает ненулевой код, когда служба не работает, — это
    // не ошибка, а ответ. Слова в нём не переводятся: они часть интерфейса
    // systemd для скриптов.
    let answer = match command::run(SYSTEMCTL, &["is-active", UNIT]) {
        Ok(answer) => answer,
        Err(_) => return Ok(ServiceStatus::Stopped),
    };

    Ok(match answer.trim() {
        "active" => ServiceStatus::Running,
        "activating" | "deactivating" => ServiceStatus::Transitioning,
        _ => ServiceStatus::Stopped,
    })
}

/// Путь к файлу, который зарегистрирован службой.
pub fn registered_executable() -> PlatformResult<Option<PathBuf>> {
    let Ok(text) = std::fs::read_to_string(UNIT_PATH) else {
        return Ok(None);
    };
    Ok(executable_from(&text))
}

/// Описание службы для systemd.
///
/// Свободная функция с тестом: потерянный здесь `--service` означает службу,
/// которая поднимется окном, а `Restart` — тоннель, не переживший обрыва.
fn unit(executable: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=Penguin VPN\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} --service\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        executable.display()
    )
}

/// Путь к файлу из описания службы.
fn executable_from(unit: &str) -> Option<PathBuf> {
    let line = unit
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("ExecStart="))?;
    let command = line.strip_prefix("ExecStart=")?;

    // Первое слово — сам файл, остальное аргументы.
    command
        .split_whitespace()
        .next()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

/// Выполняет команду systemd.
fn run(arguments: &[&str]) -> PlatformResult<()> {
    command::run(SYSTEMCTL, arguments)
        .map(|_| ())
        .map_err(|err| err.into_error(PlatformError::Service, "управление службой"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_starts_the_service_role() {
        // Без `--service` файл откроет окно — под системной учётной записью и
        // без экрана, то есть не откроет вовсе.
        let text = unit(Path::new("/usr/bin/penguin"));
        assert!(
            text.contains("ExecStart=/usr/bin/penguin --service"),
            "{text}"
        );
    }

    #[test]
    fn the_unit_survives_a_failure() {
        // Тоннель, не переживший обрыва, — это kill switch, оставшийся
        // включённым, и машина без сети.
        let text = unit(Path::new("/usr/bin/penguin"));
        assert!(text.contains("Restart=on-failure"), "{text}");
    }

    #[test]
    fn the_unit_starts_with_the_system() {
        let text = unit(Path::new("/usr/bin/penguin"));
        assert!(text.contains("WantedBy=multi-user.target"), "{text}");
    }

    #[test]
    fn the_executable_reads_back_without_its_arguments() {
        // Иначе проверка «та ли это программа» сравнивала бы путь с командой
        // и всегда отвечала «не та».
        let text = unit(Path::new("/usr/bin/penguin"));
        assert_eq!(
            executable_from(&text),
            Some(PathBuf::from("/usr/bin/penguin"))
        );
    }

    #[test]
    fn a_unit_without_a_command_names_nothing() {
        assert!(executable_from("[Unit]\nDescription=Penguin\n").is_none());
        assert!(executable_from("ExecStart=\n").is_none());
    }
}
