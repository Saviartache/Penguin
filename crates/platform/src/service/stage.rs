//! Копия программы, которую запускает диспетчер служб (общая для Unix).
//!
//! launchd отказывается поднимать задание с внешнего тома или из дерева сборки, systemd — нет, и
//! служба ломается после перезагрузки. Поэтому в постоянное место кладётся копия во владении
//! `root`, и регистрируется она.

use std::path::Path;

use crate::error::{PlatformError, PlatformResult};

/// Ошибка с именем файла: отказ без пути не лечится.
pub(super) fn at(path: &Path, err: &std::io::Error) -> PlatformError {
    PlatformError::Service(format!("{}: {err}", path.display()))
}

/// Отказ прочитать саму программу. На macOS это чаще согласие (TCC для внешних томов, «Рабочего
/// стола», «Загрузок»), а не права, и лечится иначе.
#[cfg(target_os = "macos")]
fn unreadable_source(path: &Path, err: &std::io::Error) -> PlatformError {
    if err.kind() != std::io::ErrorKind::PermissionDenied {
        return at(path, err);
    }
    PlatformError::Service(format!(
        "macOS не даёт службе прочитать {}: перенесите программу в /Applications \
         или разрешите ей доступ в «Конфиденциальность и безопасность»",
        path.display()
    ))
}

#[cfg(not(target_os = "macos"))]
fn unreadable_source(path: &Path, err: &std::io::Error) -> PlatformError {
    at(path, err)
}

/// Кладёт копию программы туда, откуда её запускает диспетчер.
pub(super) fn stage(source: &Path, directory: &str, target: &str) -> PlatformResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let directory = Path::new(directory);
    std::fs::create_dir_all(directory).map_err(|err| at(directory, &err))?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755))
        .map_err(|err| at(directory, &err))?;
    stage_into(source, Path::new(target))
}

pub(super) fn stage_into(source: &Path, target: &Path) -> PlatformResult<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut reader = std::fs::File::open(source).map_err(|err| unreadable_source(source, &err))?;
    let modified = reader
        .metadata()
        .and_then(|meta| meta.modified())
        .map_err(|err| at(source, &err))?;

    // Через временный файл: запись поверх работающего образа даёт `ETXTBSY`.
    let temporary = target.with_extension("new");
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(at(&temporary, &err)),
    }

    // Не `fs::copy`: та переносит владельца и xattr (метку карантина, после которой launchd не
    // запустит задание).
    let mut file = std::fs::File::options()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&temporary)
        .map_err(|err| at(&temporary, &err))?;
    let copied = std::io::copy(&mut reader, &mut file)
        // Время правки — отпечаток сборки (`crate::build`): без него службу перезапускали бы по кругу.
        .and_then(|_| file.set_modified(modified))
        .and_then(|()| file.sync_all());
    drop(file);
    copied.map_err(|err| at(&temporary, &err))?;

    std::fs::rename(&temporary, target).map_err(|err| at(target, &err))
}

/// Лежит ли в копии та самая сборка, что задаёт вопрос: путь у всех сборок один, поэтому
/// сравниваются размер и время правки.
pub(super) fn runs_current_build(registered: Option<&Path>, target: &str) -> bool {
    if registered != Some(Path::new(target)) {
        return false;
    }
    let (Ok(staged), Ok(current)) = (
        std::fs::metadata(target),
        std::env::current_exe().and_then(|path| path.metadata()),
    ) else {
        return false;
    };
    same_build(&staged, &current)
}

fn same_build(staged: &std::fs::Metadata, current: &std::fs::Metadata) -> bool {
    let (Ok(staged_time), Ok(current_time)) = (staged.modified(), current.modified()) else {
        return false;
    };
    staged.len() == current.len() && staged_time == current_time
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_staged_copy_is_the_same_build_until_it_is_touched() {
        let source = std::env::current_exe().expect("own path");
        let directory = std::env::temp_dir().join(format!("penguin-stage-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("directory");

        let copy = directory.join("penguin");
        let outcome = (|| -> PlatformResult<(bool, bool)> {
            stage_into(&source, &copy)?;
            let current = source.metadata()?;
            let same = same_build(&copy.metadata()?, &current);

            std::fs::File::options()
                .write(true)
                .open(&copy)?
                .set_modified(std::time::SystemTime::now() + Duration::from_secs(60))?;
            Ok((same, same_build(&copy.metadata()?, &current)))
        })();
        std::fs::remove_dir_all(&directory).expect("cleanup");

        let (same, after_touch) = outcome.expect("staging");
        assert!(same, "копия обязана считаться той же сборкой");
        assert!(!after_touch, "другое время правки — другая сборка");
    }

    #[test]
    fn a_staged_copy_belongs_to_the_installer() {
        use std::os::unix::fs::MetadataExt;

        let directory = std::env::temp_dir().join(format!("penguin-owner-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("directory");
        let source = directory.join("source");
        std::fs::write(&source, b"penguin").expect("source");

        let copy = directory.join("penguin");
        let owner = stage_into(&source, &copy).and_then(|()| Ok(copy.metadata()?.uid()));
        std::fs::remove_dir_all(&directory).expect("cleanup");

        assert_eq!(
            owner.expect("staging"),
            nix::unistd::Uid::effective().as_raw()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_staged_copy_carries_no_quarantine_mark() {
        let directory = std::env::temp_dir().join(format!("penguin-marks-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("directory");
        let source = directory.join("source");
        std::fs::write(&source, b"penguin").expect("source");
        assert!(
            std::process::Command::new("/usr/bin/xattr")
                .args(["-w", "com.apple.quarantine", "0081;0;test;"])
                .arg(&source)
                .status()
                .expect("xattr")
                .success()
        );

        let copy = directory.join("penguin");
        let staged = stage_into(&source, &copy);
        let marks = std::process::Command::new("/usr/bin/xattr")
            .arg(&copy)
            .output()
            .expect("xattr");
        std::fs::remove_dir_all(&directory).expect("cleanup");

        staged.expect("staging");
        // `com.apple.provenance` ставит сама система; проверяется только карантин.
        let names = String::from_utf8_lossy(&marks.stdout);
        assert!(
            !names.lines().any(|name| name == "com.apple.quarantine"),
            "{names}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_refused_source_is_not_reported_as_missing_rights() {
        let denied = unreadable_source(
            Path::new("/Volumes/SSD/penguin"),
            &std::io::ErrorKind::PermissionDenied.into(),
        );
        assert!(!denied.needs_privileges(), "{denied}");
        assert!(denied.to_string().contains("/Applications"), "{denied}");

        let missing = unreadable_source(
            Path::new("/Volumes/SSD/penguin"),
            &std::io::ErrorKind::NotFound.into(),
        );
        assert!(!missing.to_string().contains("/Applications"), "{missing}");
    }
}
