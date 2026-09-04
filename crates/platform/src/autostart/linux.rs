//! Linux: файл автозапуска рабочего стола.
//!
//! Общий для всех окружений способ (freedesktop.org): любой файл `.desktop` в
//! `~/.config/autostart` запускается при входе. Ни systemd, ни прав
//! администратора он не требует — а автозапуск окна и не должен их требовать.

use std::path::{Path, PathBuf};

use crate::error::{PlatformError, PlatformResult};

/// Имя файла автозапуска.
const FILE: &str = "penguin.desktop";

/// Записывает файл автозапуска.
pub(super) fn write(executable: &Path) -> PlatformResult<()> {
    let path = entry_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| PlatformError::Service(format!("{}: {err}", parent.display())))?;
    }
    std::fs::write(&path, entry(executable))
        .map_err(|err| PlatformError::Service(format!("{}: {err}", path.display())))
}

/// Убирает файл автозапуска.
pub(super) fn remove() -> PlatformResult<()> {
    let path = entry_path()?;
    // Файла не было — снимать нечего, и это успех.
    if !path.exists() {
        return Ok(());
    }
    std::fs::remove_file(&path)
        .map_err(|err| PlatformError::Service(format!("{}: {err}", path.display())))
}

/// Есть ли файл автозапуска.
pub(super) fn exists() -> bool {
    entry_path().is_ok_and(|path| path.exists())
}

/// Где лежит файл автозапуска.
fn entry_path() -> PlatformResult<PathBuf> {
    // `XDG_CONFIG_HOME` важнее домашнего каталога: пользователь мог увести
    // настройки в другое место, и класть файл мимо них значит не запустить
    // ничего.
    let root = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => super::home()?.join(".config"),
    };
    Ok(entry_path_in(&root))
}

/// Где лежит файл автозапуска внутри каталога настроек.
fn entry_path_in(config_root: &Path) -> PathBuf {
    config_root.join("autostart").join(FILE)
}

/// Содержимое файла автозапуска.
///
/// Свободная функция с тестом: `Exec` без кавычек ломается на пробеле в пути,
/// а забытый `Type` превращает файл в такой, который окружение молча
/// пропустит.
fn entry(executable: &Path) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Penguin\n\
         Exec=\"{}\"\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n",
        executable.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entry_is_an_application() {
        // Без `Type` окружение молча пропустит файл, и автозапуск «включён»
        // будет только в настройках клиента.
        let text = entry(Path::new("/usr/bin/penguin"));
        assert!(text.contains("Type=Application"), "{text}");
    }

    #[test]
    fn a_path_with_spaces_stays_one_command() {
        // Путь пользователя почти всегда содержит пробел.
        let text = entry(Path::new("/home/пингвин/Мои программы/penguin"));
        assert!(
            text.contains("Exec=\"/home/пингвин/Мои программы/penguin\""),
            "{text}"
        );
    }

    #[test]
    fn the_entry_does_not_open_a_terminal() {
        // Иначе после каждого входа рядом с окном открывалось бы чёрное окно
        // консоли, которое человек не просил.
        let text = entry(Path::new("/usr/bin/penguin"));
        assert!(text.contains("Terminal=false"), "{text}");
    }

    #[test]
    fn the_entry_lives_where_the_desktop_looks_for_it() {
        // Каталог задан freedesktop.org: файл в любом другом месте окружение
        // просто не увидит.
        assert_eq!(
            entry_path_in(Path::new("/дом/.config")),
            PathBuf::from("/дом/.config/autostart/penguin.desktop")
        );
    }
}
