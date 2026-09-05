//! Descriptor-based checks before elevated filesystem access.

use std::fs::{DirBuilder, File, OpenOptions, Permissions};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, ensure};

pub(super) fn prepare_directory(path: &Path, owner: u32) -> Result<()> {
    // System parents already exist (/etc may itself be a system symlink on
    // macOS). Never recursively create ancestors or follow our own directory.
    let created = DirBuilder::new().mode(0o700).create(path);
    if !created
        .as_ref()
        .is_err_and(|err| err.kind() == std::io::ErrorKind::AlreadyExists)
    {
        created?;
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o022 == 0,
        "machine directory must be owned by the service account and not group/world writable"
    );
    file.set_permissions(Permissions::from_mode(0o700))?;
    Ok(())
}

pub(super) fn protect_config(path: &Path, owner: u32) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == owner
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0,
        "machine configuration must be a protected service-owned regular file"
    );
    file.set_permissions(Permissions::from_mode(0o600))?;
    Ok(())
}

pub(super) fn open_import(path: &Path, controller_uid: Option<u32>) -> Result<File> {
    let uid = controller_uid.context("Unix config import requires an explicit controller UID")?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("could not securely open import source")?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "import source must be a regular file");
    ensure!(
        metadata.uid() == uid,
        "import source must be owned by the controller"
    );
    Ok(file)
}
