//! Linux: файл `.desktop` в `~/.config/autostart` (freedesktop.org; без systemd и прав).

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

/// Убирает файл автозапуска; отсутствующий — успех.
pub(super) fn remove() -> PlatformResult<()> {
    let path = entry_path()?;
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

/// Где лежит файл автозапуска; `XDG_CONFIG_HOME` важнее домашнего каталога.
fn entry_path() -> PlatformResult<PathBuf> {
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

/// Содержимое файла: `Exec` в кавычках (пробел в пути), `Type` обязателен (иначе файл пропустят).
fn entry(executable: &Path) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Penguin\n\
         Exec=\"{}\" {}\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n",
        executable.display(),
        super::ARGUMENTS.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entry_is_an_application() {
        let text = entry(Path::new("/usr/bin/penguin"));
        assert!(text.contains("Type=Application"), "{text}");
    }

    #[test]
    fn a_path_with_spaces_stays_one_command() {
        let text = entry(Path::new("/home/пингвин/Мои программы/penguin"));
        assert!(
            text.contains("Exec=\"/home/пингвин/Мои программы/penguin\""),
            "{text}"
        );
    }

    #[test]
    fn the_entry_starts_the_window_in_the_tray() {
        let text = entry(Path::new("/usr/bin/penguin"));
        assert!(text.contains("Exec=\"/usr/bin/penguin\" --tray"), "{text}");
    }

    #[test]
    fn the_entry_does_not_open_a_terminal() {
        let text = entry(Path::new("/usr/bin/penguin"));
        assert!(text.contains("Terminal=false"), "{text}");
    }

    #[test]
    fn the_entry_lives_where_the_desktop_looks_for_it() {
        assert_eq!(
            entry_path_in(Path::new("/дом/.config")),
            PathBuf::from("/дом/.config/autostart/penguin.desktop")
        );
    }
}
