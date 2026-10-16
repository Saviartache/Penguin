//! macOS: launchd держит задание, пока лежит файл-запрос (`KeepAlive.PathState`). Каталог
//! запроса принадлежит пользователю окна, поэтому запуск не требует прав.

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

use crate::error::{PlatformError, PlatformResult};
use crate::service::launchd::{START_DIR, START_REQUEST};
use crate::service::stage::at;

pub(super) fn allow(controller_uid: Option<u32>) -> PlatformResult<()> {
    let Some(uid) = controller_uid else {
        return Ok(());
    };
    let directory = Path::new(START_DIR);
    match std::fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(at(directory, &err)),
    }
    // Родитель принадлежит root: подменить каталог пользователь не может.
    std::os::unix::fs::chown(directory, Some(uid), None).map_err(|err| at(directory, &err))?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .map_err(|err| at(directory, &err))
}

pub(super) fn request() -> PlatformResult<()> {
    match std::fs::File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .open(START_REQUEST)
    {
        Ok(_) => Ok(()),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            Err(PlatformError::PermissionDenied(
                "запуск службы без пароля не разрешён".to_owned(),
            ))
        }
        Err(err) => Err(at(Path::new(START_REQUEST), &err)),
    }
}

pub(super) fn withdraw() -> PlatformResult<()> {
    match std::fs::remove_file(START_REQUEST) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(at(Path::new(START_REQUEST), &err)),
    }
}
