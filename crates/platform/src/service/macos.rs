//! macOS: служба launchd.
//!
//! launchd различает «описание есть», «описание загружено» и «процесс
//! работает». Первое — файл в `/Library/LaunchDaemons`, и он переживает
//! перезагрузку; второе — команда `bootstrap`, и она держится до `bootout`;
//! третье launchd называет сам, в ответе `print`. Из этих трёх и складывается
//! состояние.

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

/// Права файла описания.
///
/// launchd проверяет их сам и отказывается грузить службу, описание которой
/// доступно на запись кому-то, кроме владельца: иначе любой желающий подменил
/// бы программу, работающую с правами системы.
const PLIST_MODE: u32 = 0o644;

/// Ставит службу.
pub fn install(executable: &Path) -> PlatformResult<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(PLIST_PATH, plist(executable))
        .map_err(|err| PlatformError::Service(format!("{PLIST_PATH}: {err}")))?;
    std::fs::set_permissions(PLIST_PATH, std::fs::Permissions::from_mode(PLIST_MODE))
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

    // Незагруженную службу надо сперва загрузить. Отказ здесь означает одно из
    // двух: служба уже загружена — тогда всё в порядке, — или загрузить её не
    // вышло. Различить их можно только одним способом: посмотреть, загружена
    // ли она теперь.
    //
    // Проверка не для порядка. Без неё настоящий отказ уходил в `debug`, а
    // следом падал `kickstart` — с невнятным «Could not find service» вместо
    // причины, по которой launchd не взял описание.
    if let Err(err) = command::run(LAUNCHCTL, &["bootstrap", DOMAIN, PLIST_PATH])
        && command::run(LAUNCHCTL, &["print", &target()]).is_err()
    {
        return Err(err.into_error(PlatformError::Service, "загрузка службы"));
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
    let Ok(report) = command::run(LAUNCHCTL, &["print", &target()]) else {
        return Ok(ServiceStatus::Stopped);
    };
    Ok(state_from(&report))
}

/// Состояние службы из ответа `launchctl print`.
///
/// Загруженная служба и работающая — разные вещи: после выхода демона описание
/// остаётся у launchd, а процесса больше нет. Считать такую службу работающей
/// значит не запустить её и ждать ответа от того, кого нет.
///
/// Слово состояния — часть машинного ответа launchd, а не сообщение человеку:
/// оно одно и то же на любом языке системы. Берётся первое: поля самой службы
/// печатаются до вложенных, а у тех есть своё `state`.
fn state_from(report: &str) -> ServiceStatus {
    match first_state(report) {
        Some("running") => ServiceStatus::Running,
        Some("spawn scheduled") => ServiceStatus::Transitioning,
        // Всё прочее — служба загружена, но не работает. Дорога отсюда одна:
        // запустить, и запуск уже загруженной ничего не ломает.
        _ => ServiceStatus::Stopped,
    }
}

/// Первое поле `state` в ответе.
fn first_state(report: &str) -> Option<&str> {
    report
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("state = "))
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
///
/// `KeepAlive` — не «всегда», а «кроме удачного выхода». Разница решающая:
/// окно останавливает службу, когда его закрывают, и с безусловным
/// `KeepAlive` launchd поднимал бы её обратно через секунду — тоннель жил бы
/// после закрытия программы.
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
         \x20 <dict>\n\
         \x20   <key>SuccessfulExit</key>\n\
         \x20   <false/>\n\
         \x20 </dict>\n\
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
    fn a_service_stopped_on_purpose_stays_stopped() {
        // Окно останавливает службу, когда его закрывают. Безусловный
        // `KeepAlive` поднял бы её обратно, и тоннель пережил бы программу.
        let text = plist(Path::new("/usr/local/bin/penguin"));
        assert!(text.contains("<key>SuccessfulExit</key>"), "{text}");

        let after = text
            .split("<key>SuccessfulExit</key>")
            .nth(1)
            .expect("есть");
        assert!(
            after.trim_start().starts_with("<false/>"),
            "удачный выход не должен перезапускать службу: {text}"
        );
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

    /// Ответ `launchctl print` с заданным состоянием службы.
    ///
    /// Вложенное `state` в нём не для красоты: launchd печатает своё состояние
    /// и у объединения ресурсов, и перепутать их — значит звать работающей
    /// службу, от которой остался один заголовок.
    fn report(state: &str) -> String {
        format!(
            "system/com.penguin.vpn = {{\n\
             \tactive count = 0\n\
             \tstate = {state}\n\
             \tprogram = /usr/local/bin/penguin\n\
             \tresource coalition = {{\n\
             \t\tstate = active\n\
             \t}}\n\
             \tjob state = exited\n\
             }}\n"
        )
    }

    #[test]
    fn a_loaded_but_dead_service_is_not_running() {
        // Служба, вышедшая по своей воле, остаётся загруженной: описание у
        // launchd есть, процесса нет. Принять её за работающую значит не
        // запустить её и ждать ответа от того, кого нет.
        assert_eq!(state_from(&report("not running")), ServiceStatus::Stopped);
    }

    #[test]
    fn a_working_service_is_running() {
        assert_eq!(state_from(&report("running")), ServiceStatus::Running);
    }

    #[test]
    fn a_service_about_to_start_is_transitioning() {
        assert_eq!(
            state_from(&report("spawn scheduled")),
            ServiceStatus::Transitioning
        );
    }

    #[test]
    fn an_unreadable_answer_is_not_taken_for_a_running_service() {
        // Молчание и незнакомый ответ лечатся одинаково — запуском; а вот
        // «работает» без основания оставило бы человека без тоннеля.
        assert_eq!(state_from(""), ServiceStatus::Stopped);
        assert_eq!(state_from("Could not find service"), ServiceStatus::Stopped);
    }
}
