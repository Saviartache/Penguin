//! macOS: registration, loading and execution are separate launchd states.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{ServiceStatus, launchd};
use crate::command;
use crate::error::{PlatformError, PlatformResult};
use launchd::{HELPER_DIR, HELPER_PATH, PLIST, PLIST_PATH, TARGET};

const LAUNCHCTL: &str = "/bin/launchctl";

/// How long to keep asking launchd to load the job.
///
/// While the previous job of the same name is being torn down, `bootstrap`
/// answers with a refusal and nothing but waiting helps. Fractions of a
/// second in practice; the shipped clients wait the same way.
const BOOTSTRAP_ATTEMPTS: u32 = 20;
const BOOTSTRAP_PAUSE: Duration = Duration::from_millis(500);

/// Stages the program and registers the job without launching it.
///
/// Repeating it is how a wrong or outdated registration is repaired: the job
/// definition and the staged copy are both overwritten in place. Nothing is
/// removed first, so a registration that cannot be written leaves the machine
/// with the service it already had.
pub fn install(executable: &Path) -> PlatformResult<()> {
    use std::os::unix::fs::PermissionsExt;

    stage(executable)?;
    let plist = Path::new(PLIST_PATH);
    std::fs::write(plist, PLIST).map_err(|err| at(plist, &err))?;
    std::fs::set_permissions(plist, std::fs::Permissions::from_mode(0o644))
        .map_err(|err| at(plist, &err))
}

/// Ошибка с именем файла.
///
/// Системный отказ без пути не лечится ничем: «Operation not permitted» может
/// прийти и от описания задания, и от копии программы, и от каталога под ней,
/// а разбираться с этими тремя надо совершенно по-разному.
fn at(path: &Path, err: &std::io::Error) -> PlatformError {
    PlatformError::Service(format!("{}: {err}", path.display()))
}

/// Отказ прочитать саму программу — почти всегда не права, а согласие.
///
/// Внешние и съёмные тома, «Рабочий стол», «Документы» и «Загрузки» macOS
/// закрывает от программ **отдельно** от прав доступа: `root` их тоже не
/// читает, если ответственное приложение согласия не получало. Снаружи это
/// неотличимо от нехватки прав — и лечится совсем другим, а установка идёт
/// в отдельном процессе, откуда сказать об этом больше негде.
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

/// Stops the job before removing its definition. Real stop failures are fatal.
pub fn uninstall() -> PlatformResult<()> {
    stop()?;
    if Path::new(PLIST_PATH).try_exists()? {
        std::fs::remove_file(PLIST_PATH)?;
    }
    match std::fs::remove_dir_all(HELPER_DIR) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Enables and starts the job without killing an already running instance.
pub fn start() -> PlatformResult<()> {
    if !Path::new(PLIST_PATH).try_exists()? {
        return Err(PlatformError::Service("service is not installed".into()));
    }
    // A ban outlives both the job and a reboot: without lifting it first the
    // bootstrap succeeds and the job still never runs.
    run(&["enable", TARGET])?;
    if report()?.is_none() {
        bootstrap()?;
    }
    run(&["kickstart", TARGET])
}

/// Unloads the job with launchd's graceful termination, ignoring only absence.
pub fn stop() -> PlatformResult<()> {
    match command::run(LAUNCHCTL, &["bootout", TARGET]) {
        Ok(_) => Ok(()),
        // A missing manager/domain must not be mistaken for a missing service.
        Err(err) if launchd::absent(err.code()) => run(&["print", "system"]),
        Err(err) => Err(err.into_error(PlatformError::Service, "stopping service")),
    }
}

/// Queries the job state without hiding manager/permission failures.
pub fn status() -> PlatformResult<ServiceStatus> {
    if !Path::new(PLIST_PATH).try_exists()? {
        return Ok(ServiceStatus::NotInstalled);
    }
    match report()? {
        Some(report) => launchd::state_from(&report),
        None => Ok(ServiceStatus::Stopped),
    }
}

/// Returns the executable only when the persisted job has the service role.
pub fn registered_executable() -> PlatformResult<Option<PathBuf>> {
    match std::fs::read_to_string(PLIST_PATH) {
        Ok(text) => Ok(launchd::executable_from(&text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Whether the registered job is the very build asking the question.
///
/// Comparing paths would answer nothing: launchd runs a copy ([`stage`]), so
/// the registered path is the same constant for every build. Size and
/// modification time are compared instead — the same pair by which
/// [`crate::build`] tells one build from another.
pub(super) fn runs_current_build() -> bool {
    if registered_executable().ok().flatten().as_deref() != Some(Path::new(HELPER_PATH)) {
        return false;
    }
    let (Ok(staged), Ok(current)) = (
        std::fs::metadata(HELPER_PATH),
        std::env::current_exe().and_then(|path| path.metadata()),
    ) else {
        return false;
    };
    same_build(&staged, &current)
}

/// Puts a copy of the program where launchd agrees to run it from.
///
/// A copy, not a link: the job then survives a rebuild, a moved application
/// and a volume that is not mounted yet when the machine boots.
fn stage(source: &Path) -> PlatformResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let directory = Path::new(HELPER_DIR);
    std::fs::create_dir_all(directory).map_err(|err| at(directory, &err))?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755))
        .map_err(|err| at(directory, &err))?;
    stage_into(source, Path::new(HELPER_PATH))
}

fn stage_into(source: &Path, target: &Path) -> PlatformResult<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut reader = std::fs::File::open(source).map_err(|err| unreadable_source(source, &err))?;
    let modified = reader
        .metadata()
        .and_then(|meta| meta.modified())
        .map_err(|err| at(source, &err))?;

    // Through a temporary file: writing over a running image is `ETXTBSY`,
    // while renaming leaves it alone.
    let temporary = target.with_extension("new");
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(at(&temporary, &err)),
    }

    // Byte by byte rather than `fs::copy`: that one carries the source's
    // owner and extended attributes across. The daemon runs as root, and a
    // copy left owned by whoever built it is a way in; a copy that inherited
    // the quarantine mark launchd refuses to run at all. Written by hand, the
    // file belongs to the installing account and carries nothing extra.
    let mut file = std::fs::File::options()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&temporary)
        .map_err(|err| at(&temporary, &err))?;
    let copied = std::io::copy(&mut reader, &mut file)
        // The modification time is the build fingerprint (`crate::build`).
        // Lost here, the window would call the service stale on every launch
        // and restart it in circles.
        .and_then(|_| file.set_modified(modified))
        .and_then(|()| file.sync_all());
    drop(file);
    copied.map_err(|err| at(&temporary, &err))?;

    std::fs::rename(&temporary, target).map_err(|err| at(target, &err))
}

/// Loads the job, sitting out launchd's refusals.
fn bootstrap() -> PlatformResult<()> {
    let mut attempt = 1;
    loop {
        match command::run(LAUNCHCTL, &["bootstrap", "system", PLIST_PATH]) {
            Ok(_) => return Ok(()),
            Err(err) if attempt >= BOOTSTRAP_ATTEMPTS => {
                return Err(err.into_error(PlatformError::Service, "loading service"));
            }
            Err(_) => {
                attempt += 1;
                std::thread::sleep(BOOTSTRAP_PAUSE);
            }
        }
    }
}

fn same_build(staged: &std::fs::Metadata, current: &std::fs::Metadata) -> bool {
    let (Ok(staged_time), Ok(current_time)) = (staged.modified(), current.modified()) else {
        return false;
    };
    staged.len() == current.len() && staged_time == current_time
}

fn report() -> PlatformResult<Option<String>> {
    match command::run(LAUNCHCTL, &["print", TARGET]) {
        Ok(report) => Ok(Some(report)),
        Err(err) if launchd::absent(err.code()) => {
            run(&["print", "system"])?;
            Ok(None)
        }
        Err(err) => Err(err.into_error(PlatformError::Service, "querying service")),
    }
}

fn run(arguments: &[&str]) -> PlatformResult<()> {
    command::run(LAUNCHCTL, arguments)
        .map(|_| ())
        .map_err(|err| err.into_error(PlatformError::Service, "service management"))
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn a_staged_copy_belongs_to_the_installer_and_carries_no_marks() {
        use std::os::unix::fs::MetadataExt;

        // `fs::copy` перенесла бы и владельца, и метку карантина: первое —
        // это чужой файл, запускаемый под `root`, второе — задание, которое
        // launchd не запустит вовсе.
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
        let owner = stage_into(&source, &copy).and_then(|()| Ok(copy.metadata()?.uid()));
        let marks = std::process::Command::new("/usr/bin/xattr")
            .arg(&copy)
            .output()
            .expect("xattr");
        std::fs::remove_dir_all(&directory).expect("cleanup");

        assert_eq!(
            owner.expect("staging"),
            nix::unistd::Uid::effective().as_raw()
        );
        assert!(
            marks.stdout.is_empty(),
            "{}",
            String::from_utf8_lossy(&marks.stdout)
        );
    }
}
