//! Root-owned approval record. Only the elevated helper writes this file.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use nix::fcntl::{Flock, FlockArg};
use nix::libc::{O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK};
use nix::unistd::{Uid, User};

use crate::{IpcError, IpcResult, policy};

const DIRECTORY: &str = "/etc/penguin";
const RECORD: &str = "controller";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

pub(crate) fn authorize(uid: u32) -> IpcResult<bool> {
    if !Uid::effective().is_root() {
        return Err(IpcError::AccessDenied);
    }
    if uid == 0 {
        return Ok(false);
    }
    if uid == u32::MAX
        || User::from_uid(Uid::from_raw(uid))
            .map_err(std::io::Error::from)?
            .is_none()
    {
        return Err(IpcError::InvalidController("unknown Unix UID"));
    }
    write_to(
        Path::new(DIRECTORY),
        uid,
        0,
        &crate::transport::unix::service_path(),
    )
}

pub(crate) fn approved() -> IpcResult<Option<u32>> {
    read_from(Path::new(DIRECTORY), 0)
}

fn directory_handle(directory: &Path, owner: u32) -> IpcResult<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(directory)?;
    let meta = file.metadata()?;
    if !policy::protected_directory(meta.uid(), meta.mode(), meta.is_dir(), owner) {
        return Err(IpcError::InvalidController(
            "controller directory is not protected and root-owned",
        ));
    }
    Ok(file)
}

fn read_from(directory: &Path, owner: u32) -> IpcResult<Option<u32>> {
    let _directory = match directory_handle(directory, owner) {
        Ok(file) => file,
        Err(IpcError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(directory.join(RECORD))
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let meta = file.metadata()?;
    if !policy::private_record(meta.uid(), meta.mode(), meta.is_file(), meta.nlink(), owner) {
        return Err(IpcError::InvalidController(
            "approval must be a root-owned 0600 regular file with one link",
        ));
    }
    let mut raw = String::new();
    file.take(12).read_to_string(&mut raw)?;
    policy::parse_controller(&raw)
        .map(Some)
        .ok_or(IpcError::InvalidController(
            "approval must contain one nonroot UID",
        ))
}

fn socket_requires_restart(path: &Path, uid: u32, owner: u32) -> IpcResult<bool> {
    let directory = path.parent().ok_or(IpcError::AccessDenied)?;
    let _directory = match directory_handle(directory, owner) {
        Ok(handle) => handle,
        Err(IpcError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    if !meta.file_type().is_socket() {
        return Err(IpcError::InvalidController(
            "system endpoint is not a Unix socket",
        ));
    }
    Ok(meta.uid() != uid)
}

// The owner and paths are explicit so filesystem tests need no root or system endpoints.
// Production callers always require UID zero.
fn write_to(directory: &Path, uid: u32, owner: u32, socket: &Path) -> IpcResult<bool> {
    if uid == 0 {
        return Ok(false);
    }
    if uid == u32::MAX {
        return Err(IpcError::InvalidController("invalid Unix UID"));
    }
    // /etc is a trusted system parent (a system symlink on macOS). Never
    // create arbitrary ancestors or follow a symlink for our own directory.
    match std::fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err.into()),
    }
    let handle = directory_handle(directory, owner)?;
    // Lock the stable directory, not the record that rename replaces.
    let handle = Flock::lock(handle, FlockArg::LockExclusive)
        .map_err(|(_, err)| std::io::Error::from(err))?;
    let approved = read_from(directory, owner)?;
    // Keep approval and socket inspection under the same lock. An earlier
    // helper may have saved this UID but failed to restart the old listener.
    let restart = socket_requires_restart(socket, uid, owner)?;
    if approved == Some(uid) {
        return Ok(restart);
    }
    for _ in 0..100 {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temp = directory.join(format!(".controller-{}-{sequence}", std::process::id()));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
        {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        };
        let result = (|| -> IpcResult<bool> {
            // Creation is never broader than 0600; restore bits a restrictive
            // umask may remove, using the exclusive handle before writing.
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            writeln!(file, "{uid}")?;
            file.sync_all()?;
            std::fs::rename(&temp, directory.join(RECORD))?;
            handle.sync_all()?;
            Ok(true)
        })();
        let _ = std::fs::remove_file(&temp);
        return result;
    }
    Err(IpcError::InvalidController(
        "cannot create an exclusive approval temporary file",
    ))
}

#[cfg(test)]
#[path = "controller_tests.rs"]
mod tests;
