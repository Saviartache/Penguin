//! macOS: агент запуска текущего пользователя.
//!
//! Не служба: агент из `~/Library/LaunchAgents` работает под самим
//! пользователем и поднимается при его входе, а не вместе с системой. Прав
//! администратора он не требует — а автозапуск окна и не должен их требовать.

use std::path::{Path, PathBuf};

use crate::command;
use crate::error::{PlatformError, PlatformResult};

/// Программа управления агентами.
const LAUNCHCTL: &str = "/bin/launchctl";

/// Имя агента.
const LABEL: &str = "com.penguin.gui";

/// Имя файла описания.
const FILE: &str = "com.penguin.gui.plist";

/// Записывает описание агента и загружает его.
pub(super) fn write(executable: &Path) -> PlatformResult<()> {
    let path = entry_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| PlatformError::Service(format!("{}: {err}", parent.display())))?;
    }
    std::fs::write(&path, agent(executable))
        .map_err(|err| PlatformError::Service(format!("{}: {err}", path.display())))?;

    // Без загрузки агент заработает только со следующего входа в систему, и
    // человек решит, что переключатель не сработал.
    load(&path);
    Ok(())
}

/// Убирает описание агента.
pub(super) fn remove() -> PlatformResult<()> {
    let path = entry_path()?;
    // Файла не было — снимать нечего, и это успех.
    if !path.exists() {
        return Ok(());
    }

    unload();
    std::fs::remove_file(&path)
        .map_err(|err| PlatformError::Service(format!("{}: {err}", path.display())))
}

/// Есть ли описание агента.
pub(super) fn exists() -> bool {
    entry_path().is_ok_and(|path| path.exists())
}

/// Где лежит описание агента.
fn entry_path() -> PlatformResult<PathBuf> {
    Ok(entry_path_in(&super::home()?))
}

/// Где лежит описание агента внутри домашнего каталога.
fn entry_path_in(home: &Path) -> PathBuf {
    home.join("Library").join("LaunchAgents").join(FILE)
}

/// Загружает агента.
///
/// Неудача не отменяет включения: файл записан, и со следующего входа агент
/// заработает в любом случае.
fn load(path: &Path) {
    let target = format!("gui/{}", nix::unistd::getuid().as_raw());
    if let Err(err) = command::run(
        LAUNCHCTL,
        &["bootstrap", &target, &path.display().to_string()],
    ) {
        tracing::debug!(?err, "агент не загружен до следующего входа");
    }
}

/// Выгружает агента.
fn unload() {
    let target = format!("gui/{}/{LABEL}", nix::unistd::getuid().as_raw());
    if let Err(err) = command::run(LAUNCHCTL, &["bootout", &target]) {
        tracing::debug!(?err, "выгружать было нечего");
    }
}

/// Описание агента.
///
/// Свободная функция с тестом: забытый `RunAtLoad` означает автозапуск,
/// который «включён», но ничего не запускает.
fn agent(executable: &Path) -> String {
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
         \x20 </array>\n\
         \x20 <key>RunAtLoad</key>\n\
         \x20 <true/>\n\
         </dict>\n\
         </plist>\n",
        escape(&executable.display().to_string())
    )
}

/// Экранирует то, что в XML значит не себя.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_actually_runs_at_login() {
        // Без `RunAtLoad` автозапуск «включён», но ничего не запускает.
        let text = agent(Path::new(
            "/Applications/Penguin.app/Contents/MacOS/penguin",
        ));
        assert!(text.contains("<key>RunAtLoad</key>"), "{text}");
        assert!(text.contains("<true/>"), "{text}");
    }

    #[test]
    fn the_agent_names_the_window_not_the_service() {
        // Аргументов нет вовсе: без них программа открывает окно, а это и
        // есть то, чего человек хочет после входа.
        let text = agent(Path::new("/usr/local/bin/penguin"));
        assert!(!text.contains("--service"), "{text}");
        assert!(
            text.contains("<string>/usr/local/bin/penguin</string>"),
            "{text}"
        );
    }

    #[test]
    fn an_ampersand_in_the_path_does_not_break_the_file() {
        let text = agent(Path::new("/Applications/Ссылки & копии/penguin"));
        assert!(text.contains("&amp;"), "{text}");
    }

    #[test]
    fn the_agent_lives_where_the_system_looks_for_it() {
        // Каталог задан системой: файл в любом другом месте launchd не
        // увидит.
        assert_eq!(
            entry_path_in(Path::new("/Users/пингвин")),
            PathBuf::from("/Users/пингвин/Library/LaunchAgents/com.penguin.gui.plist")
        );
    }
}
