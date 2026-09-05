use super::*;
use std::path::PathBuf;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        loop {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "penguin-approval-test-{}-{sequence}",
                std::process::id()
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("temporary directory: {err}"),
            }
        }
    }

    fn directory(&self) -> PathBuf {
        self.0.join("approval")
    }

    fn write(&self, uid: u32) -> IpcResult<bool> {
        write_to(
            &self.directory(),
            uid,
            Uid::effective().as_raw(),
            &self.socket(),
        )
    }

    fn socket(&self) -> PathBuf {
        self.0.join("control.sock")
    }

    fn read(&self) -> IpcResult<Option<u32>> {
        read_from(&self.directory(), Uid::effective().as_raw())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn approval_is_atomic_private_and_idempotent() {
    let fixture = Fixture::new();
    assert_eq!(fixture.read().unwrap(), None);
    assert!(fixture.write(1001).unwrap());
    let record = fixture.directory().join(RECORD);
    let before = std::fs::metadata(&record).unwrap();
    assert_eq!(before.mode() & 0o7777, 0o600);
    assert_eq!(before.uid(), Uid::effective().as_raw());
    assert_eq!(before.nlink(), 1);
    assert_eq!(std::fs::read_to_string(&record).unwrap(), "1001\n");
    assert!(!fixture.write(1001).unwrap());
    assert!(!fixture.write(0).unwrap());
    assert_eq!(std::fs::metadata(&record).unwrap().ino(), before.ino());
    assert!(fixture.write(1002).unwrap());
    assert_eq!(fixture.read().unwrap(), Some(1002));
    assert_ne!(std::fs::metadata(&record).unwrap().ino(), before.ino());
    assert_eq!(std::fs::read_dir(fixture.directory()).unwrap().count(), 1);
}

#[test]
fn root_is_a_noop_even_without_an_existing_directory() {
    let fixture = Fixture::new();
    assert!(!fixture.write(0).unwrap());
    assert!(!fixture.directory().exists());
    assert!(fixture.write(u32::MAX).is_err());
    assert!(!fixture.directory().exists());
}

#[test]
fn concurrent_identical_approvals_change_access_only_once() {
    let fixture = Fixture::new();
    let barrier = std::sync::Barrier::new(8);
    let changed = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    fixture.write(1001).unwrap()
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|changed| *changed)
            .count()
    });
    assert_eq!(changed, 1);
    assert_eq!(fixture.read().unwrap(), Some(1001));
}

#[test]
fn unsafe_record_modes_are_not_read_or_replaced() {
    let fixture = Fixture::new();
    assert!(fixture.write(1001).unwrap());
    let record = fixture.directory().join(RECORD);
    for mode in [0o644, 0o660, 0o666, 0o4600] {
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(fixture.read().is_err());
        assert!(fixture.write(1002).is_err());
        assert_eq!(std::fs::read_to_string(&record).unwrap(), "1001\n");
    }
}

#[test]
fn malformed_or_nonregular_records_are_rejected() {
    let fixture = Fixture::new();
    assert!(fixture.write(1001).unwrap());
    let record = fixture.directory().join(RECORD);
    for raw in [
        "",
        "0\n",
        "1001\n1002\n",
        "1001\n\n",
        "4294967295",
        "12345678901234567890",
    ] {
        std::fs::write(&record, raw).unwrap();
        assert!(fixture.read().is_err());
        assert!(fixture.write(1002).is_err());
        assert_eq!(std::fs::read_to_string(&record).unwrap(), raw);
    }
    std::fs::remove_file(&record).unwrap();
    std::fs::create_dir(&record).unwrap();
    assert!(fixture.read().is_err());
    std::fs::remove_dir(&record).unwrap();
    nix::unistd::mkfifo(
        &record,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    // O_NONBLOCK ensures a malicious FIFO cannot hang the helper.
    assert!(fixture.read().is_err());
    assert!(fixture.write(1002).is_err());
}

#[test]
fn record_links_are_not_followed_or_replaced() {
    let fixture = Fixture::new();
    assert!(fixture.write(1001).unwrap());
    let record = fixture.directory().join(RECORD);
    let target = fixture.0.join("target");
    std::fs::rename(&record, &target).unwrap();
    std::os::unix::fs::symlink(&target, &record).unwrap();
    assert!(fixture.read().is_err());
    assert!(fixture.write(1002).is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "1001\n");
    std::fs::remove_file(&record).unwrap();
    std::fs::hard_link(&target, &record).unwrap();
    assert!(fixture.read().is_err());
    assert!(fixture.write(1002).is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "1001\n");
}

#[test]
fn unsafe_or_symlinked_directories_are_rejected() {
    let fixture = Fixture::new();
    assert!(fixture.write(1001).unwrap());
    let directory = fixture.directory();
    let other_owner = Uid::effective().as_raw() ^ 1;
    assert!(read_from(&directory, other_owner).is_err());
    assert!(write_to(&directory, 1002, other_owner, &fixture.socket()).is_err());
    for mode in [0o770, 0o777] {
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(fixture.read().is_err());
        assert!(fixture.write(1002).is_err());
    }
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = fixture.0.join("target");
    std::fs::rename(&directory, &target).unwrap();
    std::os::unix::fs::symlink(&target, &directory).unwrap();
    assert!(fixture.read().is_err());
    assert!(fixture.write(1002).is_err());
    assert_eq!(
        std::fs::read_to_string(target.join(RECORD)).unwrap(),
        "1001\n"
    );
}

#[test]
fn unchanged_approval_retries_restart_until_stale_socket_is_gone() {
    let fixture = Fixture::new();
    let owner = Uid::effective().as_raw();
    let uid = if owner == 1001 { 1002 } else { 1001 };
    assert!(fixture.write(uid).unwrap());
    let record = fixture.directory().join(RECORD);
    let inode = std::fs::metadata(&record).unwrap().ino();
    let listener = std::os::unix::net::UnixListener::bind(fixture.socket()).unwrap();
    assert!(fixture.write(uid).unwrap());
    assert!(fixture.write(uid).unwrap());
    assert!(!fixture.write(0).unwrap());
    assert_eq!(fixture.read().unwrap(), Some(uid));
    assert_eq!(std::fs::metadata(&record).unwrap().ino(), inode);
    assert!(!socket_requires_restart(&fixture.socket(), owner, owner).unwrap());
    drop(listener);
    std::fs::remove_file(fixture.socket()).unwrap();
    assert!(!fixture.write(uid).unwrap());
}

#[test]
fn missing_socket_or_directory_does_not_require_restart() {
    let fixture = Fixture::new();
    let owner = Uid::effective().as_raw();
    assert!(!socket_requires_restart(&fixture.socket(), 1001, owner).unwrap());
    assert!(
        !socket_requires_restart(&fixture.0.join("missing/control.sock"), 1001, owner).unwrap()
    );
}

#[test]
fn unexpected_socket_entries_fail_closed_without_changing_approval() {
    let fixture = Fixture::new();
    assert!(fixture.write(1001).unwrap());
    let socket = fixture.socket();
    std::fs::write(&socket, "not a socket").unwrap();
    assert!(fixture.write(1001).is_err());
    assert!(fixture.write(1002).is_err());
    std::fs::remove_file(&socket).unwrap();
    std::fs::create_dir(&socket).unwrap();
    assert!(fixture.write(1001).is_err());
    std::fs::remove_dir(&socket).unwrap();
    let target = fixture.0.join("target.sock");
    std::os::unix::fs::symlink(&target, &socket).unwrap();
    assert!(fixture.write(1001).is_err());
    let _listener = std::os::unix::net::UnixListener::bind(&target).unwrap();
    assert!(fixture.write(1001).is_err());
    assert!(fixture.write(1002).is_err());
    assert!(!fixture.write(0).unwrap());
    assert_eq!(fixture.read().unwrap(), Some(1001));
}

#[test]
fn socket_parent_must_be_protected_owned_and_not_a_symlink() {
    let fixture = Fixture::new();
    let owner = Uid::effective().as_raw();
    assert!(socket_requires_restart(&fixture.socket(), 1001, owner ^ 1).is_err());
    for mode in [0o770, 0o777] {
        std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(fixture.write(1001).is_err());
    }
    std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(fixture.read().unwrap(), None);
    let alias = fixture.0.join("alias");
    std::os::unix::fs::symlink(&fixture.0, &alias).unwrap();
    assert!(socket_requires_restart(&alias.join("control.sock"), 1001, owner).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::write(&alias, "not a directory").unwrap();
    assert!(socket_requires_restart(&alias.join("control.sock"), 1001, owner).is_err());
}

#[test]
fn public_authorization_requires_root_without_touching_system_paths() {
    if Uid::effective().is_root() {
        assert!(!authorize(0).unwrap());
        assert!(matches!(
            authorize(u32::MAX),
            Err(IpcError::InvalidController(_))
        ));
    } else {
        assert!(matches!(authorize(1001), Err(IpcError::AccessDenied)));
        assert!(matches!(authorize(0), Err(IpcError::AccessDenied)));
    }
}
