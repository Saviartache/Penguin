//! Подмена исполняемого файла на новый.

use std::ffi::OsString;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use crate::error::{UpdateError, UpdateResult};

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Кладёт `bytes` на место `target`: рядом пишется временный файл, затем подмена одним
/// переименованием, так что никто не увидит половину файла.
///
/// Windows не даёт перезаписать работающий exe, но даёт переименовать: прежний уходит в `.old`
/// и убирается при следующем запуске ([`remove_leftovers`]).
pub fn replace_executable(target: &Path, bytes: &[u8]) -> UpdateResult<()> {
    let fresh = sibling(target, ".new");
    write_fresh(&fresh, bytes)?;

    let swapped = if cfg!(windows) {
        swap_keeping_old(&fresh, target)
    } else {
        std::fs::rename(&fresh, target).map_err(|err| UpdateError::io(target, err))
    };
    if swapped.is_err() {
        let _ = std::fs::remove_file(&fresh);
    }
    swapped
}

fn write_fresh(path: &Path, bytes: &[u8]) -> UpdateResult<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o755);

    let written = options.open(path).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    written.map_err(|err| match err.kind() {
        ErrorKind::PermissionDenied => {
            UpdateError::NotWritable(path.parent().unwrap_or(path).to_path_buf())
        }
        _ => UpdateError::io(path, err),
    })
}

fn swap_keeping_old(fresh: &Path, target: &Path) -> UpdateResult<()> {
    let old = sibling(target, ".old");
    match std::fs::remove_file(&old) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(UpdateError::io(&old, err)),
    }
    std::fs::rename(target, &old).map_err(|err| UpdateError::io(target, err))?;
    if let Err(err) = std::fs::rename(fresh, target) {
        // Без исполняемого файла на месте приложение не запустится: вернуть прежний.
        let _ = std::fs::rename(&old, target);
        return Err(UpdateError::io(target, err));
    }
    Ok(())
}

/// Убирает то, что осталось от прошлой подмены; занятый файл подождёт до следующего запуска.
pub fn remove_leftovers() {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    for suffix in [".old", ".new"] {
        let _ = std::fs::remove_file(sibling(&executable, suffix));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("penguin-update-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("каталог");
        directory
    }

    #[test]
    fn the_file_is_replaced_whole_and_no_temporary_stays() {
        let directory = scratch("replace");
        let target = directory.join("penguin");
        std::fs::write(&target, b"old").expect("старый");

        replace_executable(&target, b"new").expect("подмена");

        assert_eq!(std::fs::read(&target).expect("файл"), b"new");
        assert!(!sibling(&target, ".new").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = target.metadata().expect("права").permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "файл обязан запускаться");
        }
        std::fs::remove_dir_all(&directory).expect("уборка");
    }

    #[test]
    fn a_missing_directory_fails_and_leaves_nothing() {
        let directory = scratch("missing");
        let target = directory.join("absent").join("penguin");

        assert!(replace_executable(&target, b"new").is_err());
        std::fs::remove_dir_all(&directory).expect("уборка");
    }

    #[cfg(unix)]
    #[test]
    fn a_read_only_directory_is_reported_as_not_writable() {
        use std::os::unix::fs::PermissionsExt;

        let directory = scratch("readonly");
        let target = directory.join("penguin");
        std::fs::write(&target, b"old").expect("старый");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555))
            .expect("права");

        // Под root права каталога не действуют.
        let probe = directory.join("probe");
        let enforced = std::fs::write(&probe, b"").is_err();
        let result = replace_executable(&target, b"new");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
            .expect("права");
        std::fs::remove_dir_all(&directory).expect("уборка");

        if enforced {
            assert!(
                matches!(result, Err(UpdateError::NotWritable(_))),
                "{result:?}"
            );
        }
    }

    #[test]
    fn the_windows_swap_keeps_the_old_file_aside_and_restores_on_failure() {
        let directory = scratch("swap");
        let target = directory.join("penguin.exe");
        let fresh = directory.join("penguin.exe.new");
        std::fs::write(&target, b"old").expect("старый");
        std::fs::write(&fresh, b"new").expect("новый");

        swap_keeping_old(&fresh, &target).expect("подмена");
        assert_eq!(std::fs::read(&target).expect("файл"), b"new");
        assert_eq!(
            std::fs::read(sibling(&target, ".old")).expect("прежний"),
            b"old"
        );

        // Заменить нечем — действующий файл обязан вернуться на место.
        let err = swap_keeping_old(&directory.join("none"), &target);
        assert!(err.is_err());
        assert_eq!(std::fs::read(&target).expect("файл"), b"new");
        std::fs::remove_dir_all(&directory).expect("уборка");
    }
}
