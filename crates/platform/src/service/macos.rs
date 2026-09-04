//! macOS: служба launchd.
//!
//! launchd различает «описание есть» и «описание загружено». Первое — файл в
//! `/Library/LaunchDaemons`, и он переживает перезагрузку; второе — команда
//! `bootstrap`, и она держится до `bootout`. На этом различии и построено
//! состояние: файл есть, но не загружено — служба остановлена.

use std::path::{Path, PathBuf};

use crate::command;
use crate::error::{PlatformError, PlatformResult};
use crate::service::ServiceStatus;

/// Программа управления службами.
const LAUNCHCTL: &str = "/bin/launchctl";

/// Имя службы в launchd.
const LABEL: &str = "com.penguin.vpn";

/// Где лежит описание службы.
const PLIST_PATH: &str = "/Library/LaunchDaemons/com.penguin.vpn.plist";

/// Область, в которой живёт служба: системная, а не пользовательская.
const DOMAIN: &str = "system";

/// Ставит службу.
pub fn install(executable: &Path) -> PlatformResult<()> {
    std::fs::write(PLIST_PATH, plist(executable))
        .map_err(|err| PlatformError::Service(format!("{PLIST_PATH}: {err}")))?;

    // Загрузка ставит службу на автозапуск и поднимает её сразу: `RunAtLoad`
    // в описании означает именно это.
    run(&["bootstrap", DOMAIN, PLIST_PATH])
}

/// Убирает службу.
pub fn uninstall() -> PlatformResult<()> {
    // Выгрузка может не удаться потому, что служба и так не загружена; файл
    // убрать это не мешает.
    if let Err(err) = command::run(LAUNCHCTL, &["bootout", &target()]) {
        tracing::debug!(?err, "выгружать было нечего");
    }
    if Path::new(PLIST_PATH).exists() {
        std::fs::remove_file(PLIST_PATH)
            .map_err(|err| PlatformError::Service(format!("{PLIST_PATH}: {err}")))?;
    }
    Ok(())
}

/// Запускает службу.
pub fn start() -> PlatformResult<()> {
    if !Path::new(PLIST_PATH).exists() {
        return Err(PlatformError::Service("служба не установлена".to_owned()));
    }

    // Незагруженную службу надо сперва загрузить; уже загруженная ответит
    // отказом, и это не повод считать запуск неудавшимся.
    if let Err(err) = command::run(LAUNCHCTL, &["bootstrap", DOMAIN, PLIST_PATH]) {
        tracing::debug!(?err, "служба уже загружена");
    }
    run(&["kickstart", "-k", &target()])
}

/// Останавливает службу.
///
/// Выгрузкой, а не сигналом: у launchd нет команды «остановить и оставить
/// загруженной», а `KeepAlive` поднял бы службу обратно.
pub fn stop() -> PlatformResult<()> {
    run(&["bootout", &target()])
}

/// Состояние службы.
pub fn status() -> PlatformResult<ServiceStatus> {
    if !Path::new(PLIST_PATH).exists() {
        return Ok(ServiceStatus::NotInstalled);
    }

    // `print` возвращает ненулевой код, когда служба не загружена, — это не
    // ошибка, а ответ.
    if command::run(LAUNCHCTL, &["print", &target()]).is_err() {
        return Ok(ServiceStatus::Stopped);
    }
    Ok(ServiceStatus::Running)
}

/// Путь к файлу, который зарегистрирован службой.
pub fn registered_executable() -> PlatformResult<Option<PathBuf>> {
    let Ok(text) = std::fs::read_to_string(PLIST_PATH) else {
        return Ok(None);
    };
    Ok(executable_from(&text))
}

/// Адрес службы для `launchctl`.
fn target() -> String {
    format!("{DOMAIN}/{LABEL}")
}

/// Описание службы для launchd.
///
/// Свободная функция с тестом: потерянный здесь `--service` означает службу,
/// которая поднимется окном, а `KeepAlive` — тоннель, не переживший обрыва.
fn plist(executable: &Path) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \x20 <key>Label</key>\n\
         \x20 <string>{LABEL}</string>\n\
         \x20 <key>ProgramArguments</key>\n\
         \x20 <array>\n\
         \x20   <string>{}</string>\n\
         \x20   <string>--service</string>\n\
         \x20 </array>\n\
         \x20 <key>RunAtLoad</key>\n\
         \x20 <true/>\n\
         \x20 <key>KeepAlive</key>\n\
         \x20 <true/>\n\
         </dict>\n\
         </plist>\n",
        escape(&executable.display().to_string())
    )
}

/// Экранирует то, что в XML значит не себя.
///
/// Путь приходит из файловой системы, и `&` в имени каталога — законный
/// символ. Незаэкранированный, он превращает описание службы в файл, который
/// launchd не прочтёт.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Путь к файлу из описания службы.
///
/// Берётся первая строка внутри `ProgramArguments`: она и есть сама
/// программа, остальные — её аргументы.
fn executable_from(plist: &str) -> Option<PathBuf> {
    let arguments = plist.split("<key>ProgramArguments</key>").nth(1)?;
    let value = arguments
        .split("<string>")
        .nth(1)?
        .split("</string>")
        .next()?;

    let value = unescape(value.trim());
    (!value.is_empty()).then(|| PathBuf::from(value))
}

/// Возвращает экранированному тексту исходный вид.
fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Выполняет команду launchd.
fn run(arguments: &[&str]) -> PlatformResult<()> {
    command::run(LAUNCHCTL, arguments)
        .map(|_| ())
        .map_err(|err| err.into_error(PlatformError::Service, "управление службой"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_description_starts_the_service_role() {
        // Без `--service` файл откроет окно — под системной учётной записью и
        // без экрана, то есть не откроет вовсе.
        let text = plist(Path::new("/usr/local/bin/penguin"));
        assert!(
            text.contains("<string>/usr/local/bin/penguin</string>"),
            "{text}"
        );
        assert!(text.contains("<string>--service</string>"), "{text}");
    }

    #[test]
    fn the_service_survives_a_failure_and_a_reboot() {
        let text = plist(Path::new("/usr/local/bin/penguin"));
        assert!(text.contains("<key>KeepAlive</key>"), "{text}");
        assert!(text.contains("<key>RunAtLoad</key>"), "{text}");
    }

    #[test]
    fn an_ampersand_in_the_path_does_not_break_the_file() {
        // `&` — законный символ в имени каталога, и незаэкранированным он
        // превращает описание в файл, который launchd не прочтёт.
        let text = plist(Path::new("/Applications/Ссылки & копии/penguin"));
        assert!(text.contains("&amp;"), "{text}");
        assert!(!text.contains(" & "), "{text}");
    }

    #[test]
    fn the_executable_reads_back_without_its_arguments() {
        // Иначе проверка «та ли это программа» сравнивала бы путь с командой
        // и всегда отвечала «не та».
        let text = plist(Path::new("/usr/local/bin/penguin"));
        assert_eq!(
            executable_from(&text),
            Some(PathBuf::from("/usr/local/bin/penguin"))
        );
    }

    #[test]
    fn an_escaped_path_reads_back_as_it_was() {
        let path = Path::new("/Applications/Ссылки & копии/penguin");
        assert_eq!(executable_from(&plist(path)), Some(path.to_path_buf()));
    }

    #[test]
    fn a_description_without_a_command_names_nothing() {
        assert!(executable_from("<plist><dict></dict></plist>").is_none());
    }
}
