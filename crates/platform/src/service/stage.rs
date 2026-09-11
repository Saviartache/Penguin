//! Копия программы, которую запускает диспетчер служб. Общая для Unix.
//!
//! Диспетчеру нельзя давать тот файл, который запустил человек. На macOS
//! launchd прямо отказывается поднимать задание с внешнего тома или из дерева
//! сборки; systemd не отказывается — и в этом вся разница между «не работает
//! сразу» и «перестало работать после перезагрузки», когда каталог сборки
//! стёрли, программу перенесли, а съёмный носитель к моменту загрузки ещё не
//! смонтирован.
//!
//! Поэтому установка кладёт копию в постоянное место, принадлежащее `root`, и
//! регистрирует **её**. Так делают все готовые клиенты: pritunl держит
//! `/Library/PrivilegedHelperTools/pritunl-client/pritunl-service` на macOS и
//! `/usr/bin/pritunl-client-service` на Linux.

use std::path::Path;

use crate::error::{PlatformError, PlatformResult};

/// Ошибка с именем файла.
///
/// Системный отказ без пути не лечится ничем: «Operation not permitted» может
/// прийти и от описания службы, и от копии программы, и от каталога под ней,
/// а разбираться с этими тремя надо совершенно по-разному.
pub(super) fn at(path: &Path, err: &std::io::Error) -> PlatformError {
    PlatformError::Service(format!("{}: {err}", path.display()))
}

/// Отказ прочитать саму программу.
///
/// На macOS это почти всегда не права, а согласие: внешние и съёмные тома,
/// «Рабочий стол», «Документы» и «Загрузки» система закрывает от программ
/// **отдельно** от прав доступа, и `root` их тоже не читает, если
/// ответственное приложение согласия не получало. Снаружи неотличимо от
/// нехватки прав, а лечится совсем другим — и установка идёт отдельным
/// процессом, откуда сказать об этом больше негде.
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
///
/// Копия, а не ссылка: задание переживает и пересборку, и перенос программы, и
/// том, который к моменту загрузки ещё не смонтирован.
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

    // Через временный файл: запись поверх работающего образа — это `ETXTBSY`,
    // а переименование его не трогает.
    let temporary = target.with_extension("new");
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(at(&temporary, &err)),
    }

    // Побайтно, а не `fs::copy`: та переносит и владельца, и расширенные
    // атрибуты. Служба работает под `root`, и копия, оставшаяся во владении
    // того, кто её собрал, — это дорога внутрь; копия, унаследовавшая метку
    // карантина, launchd не запустит вовсе. Написанный своими руками файл
    // принадлежит устанавливающей учётной записи и не несёт ничего лишнего.
    let mut file = std::fs::File::options()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&temporary)
        .map_err(|err| at(&temporary, &err))?;
    let copied = std::io::copy(&mut reader, &mut file)
        // Время правки — это отпечаток сборки (`crate::build`). Потеряв его
        // здесь, окно считало бы службу устаревшей при каждом запуске и
        // перезапускало бы её по кругу.
        .and_then(|_| file.set_modified(modified))
        .and_then(|()| file.sync_all());
    drop(file);
    copied.map_err(|err| at(&temporary, &err))?;

    std::fs::rename(&temporary, target).map_err(|err| at(target, &err))
}

/// Лежит ли в копии та самая сборка, которая сейчас задаёт вопрос.
///
/// Сравнивать пути бессмысленно: диспетчер запускает копию, и записанный путь
/// у всех сборок один и тот же. Сравниваются размер и время правки — та же
/// пара, по которой [`crate::build`] отличает одну сборку от другой.
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

            // Так выглядит служба, оставшаяся от прошлой сборки: окно обязано
            // это заметить, иначе тоннель поднимает прежний код.
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

        // `fs::copy` перенесла бы владельца: это чужой файл, запускаемый
        // под `root`.
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
        // Задание с меткой карантина launchd не запустит вовсе.
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
        // Свежий файл на нынешних macOS несёт `com.apple.provenance`: метку
        // ставит сама система, у копии она не от источника, и launchd её не
        // замечает. Проверяется не «список пуст», а «карантина нет» — метка
        // карантина должна была остаться на источнике.
        let names = String::from_utf8_lossy(&marks.stdout);
        assert!(
            !names.lines().any(|name| name == "com.apple.quarantine"),
            "{names}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_refused_source_is_not_reported_as_missing_rights() {
        // «Operation not permitted» на своём же файле — это согласие TCC, и
        // человек, услышавший «нужны права», будет искать не то.
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
