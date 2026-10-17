//! `flock` на файле: ядро снимает блокировку при любом завершении процесса.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};

use super::lock::Instance;
use crate::error::PlatformResult;

/// Дескриптор держит блокировку; закрывается без `exec` в потомков (`O_CLOEXEC`).
pub(super) type Held = Flock<File>;

pub(super) fn try_lock(instance: Instance, dir: &Path) -> PlatformResult<Option<Held>> {
    std::fs::create_dir_all(dir)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(dir.join(instance.file_name()))?;

    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(held) => Ok(Some(held)),
        Err((_, Errno::EWOULDBLOCK)) => Ok(None),
        Err((_, errno)) => Err(std::io::Error::from(errno).into()),
    }
}
