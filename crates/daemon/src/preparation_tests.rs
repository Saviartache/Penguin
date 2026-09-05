//! Filesystem-only preparation tests; never invoke service management or IPC.

#![allow(clippy::expect_used)]

use super::*;

fn fixture() -> (tempfile::TempDir, Paths, u32) {
    let temp = tempfile::tempdir().expect("temporary directory");
    let paths = Paths::rooted(temp.path().join("machine"));
    let owner = penguin_ipc::current_user_id().unwrap_or(0);
    (temp, paths, owner)
}

#[test]
fn no_source_prepares_directories_without_guessing_user_settings() {
    let (_temp, paths, owner) = fixture();
    prepare_config(&paths, None, None, owner).expect("prepare");
    assert!(paths.config_dir().is_dir());
    assert!(paths.data_dir().is_dir());
    assert!(!paths.config_file().exists());
}

#[test]
fn imports_migrates_and_does_not_replace_existing_settings() {
    let (temp, paths, owner) = fixture();
    let source = temp.path().join("user.toml");
    std::fs::write(&source, "version = 0\n[app]\nautostart = true\n").expect("source");
    prepare_config(&paths, Some(owner), Some(&source), owner).expect("import");
    let store = ConfigStore::new(paths.clone());
    let config = store.load().expect("validated migrated config");
    assert_eq!(config.version, penguin_config::schema::SCHEMA_VERSION);
    assert!(config.app.autostart);
    let before = std::fs::read(paths.config_file()).expect("imported bytes");
    std::fs::remove_file(&source).expect("remove source");
    prepare_config(&paths, None, Some(&source), owner).expect("existing config skips import");
    assert_eq!(
        std::fs::read(paths.config_file()).expect("unchanged"),
        before
    );
    assert_eq!(
        std::fs::read_dir(paths.config_dir())
            .expect("entries")
            .count(),
        2
    );
}

#[test]
fn invalid_imports_do_not_leak_input_or_publish_a_file() {
    let (temp, paths, owner) = fixture();
    let source = temp.path().join("user.toml");
    for body in [
        "password = secret-do-not-print",
        "active_profile = 'secret-do-not-print'",
        "version = 999999",
    ] {
        std::fs::write(&source, body).expect("source");
        let err =
            prepare_config(&paths, Some(owner), Some(&source), owner).expect_err("invalid import");
        assert_eq!(
            format!("{err:#}"),
            "imported configuration is invalid or unsupported"
        );
        assert!(!format!("{err:?}").contains("secret-do-not-print"));
        assert!(!paths.config_file().exists());
    }
}

#[test]
fn oversized_import_is_rejected() {
    let (temp, paths, owner) = fixture();
    let source = temp.path().join("large.toml");
    File::create(&source)
        .expect("source")
        .set_len(MAX_CONFIG_SIZE + 1)
        .expect("length");
    let err = prepare_config(&paths, Some(owner), Some(&source), owner).expect_err("size bound");
    assert!(err.to_string().contains("4 MiB"));
    assert!(!paths.config_file().exists());
}

#[test]
fn data_directory_errors_are_fatal() {
    let (_temp, paths, owner) = fixture();
    std::fs::create_dir(paths.config_dir()).expect("config directory");
    std::fs::write(paths.data_dir(), "not a directory").expect("obstruction");
    assert!(prepare_config(&paths, None, None, owner).is_err());
}

#[test]
fn publication_never_clobbers_an_existing_file() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let target = temp.path().join("config.toml");
    std::fs::write(&target, "original").expect("existing config");
    persist_new(&target, b"replacement").expect("no-clobber publication");
    assert_eq!(std::fs::read_to_string(&target).expect("read"), "original");
    assert_eq!(std::fs::read_dir(temp.path()).expect("entries").count(), 1);
}

#[cfg(unix)]
mod unix_tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::*;

    #[test]
    fn directories_and_imported_config_are_private() {
        let (temp, paths, owner) = fixture();
        let source = temp.path().join("user.toml");
        std::fs::write(&source, "version = 0").expect("source");
        std::fs::create_dir(paths.config_dir()).expect("directory");
        std::fs::set_permissions(paths.config_dir(), std::fs::Permissions::from_mode(0o755))
            .expect("old mode");
        prepare_config(&paths, Some(owner), Some(&source), owner).expect("prepare");
        for path in [paths.config_dir(), paths.data_dir()] {
            assert_eq!(
                std::fs::metadata(path).expect("directory").mode() & 0o777,
                0o700
            );
        }
        let meta = std::fs::metadata(paths.config_file()).expect("config");
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.uid(), owner);
        assert_eq!(meta.nlink(), 1);
    }

    #[test]
    fn source_requires_explicit_matching_owner_before_reading() {
        let (temp, _paths, owner) = fixture();
        let source = temp.path().join("secret");
        std::fs::write(&source, [0xff]).expect("unreadable as UTF-8");
        assert!(
            read_import(&source, None)
                .expect_err("explicit UID")
                .to_string()
                .contains("explicit")
        );
        assert!(
            read_import(&source, Some(owner ^ 1))
                .expect_err("wrong owner")
                .to_string()
                .contains("owned by the controller")
        );
    }

    #[test]
    fn source_symlink_and_directory_are_rejected() {
        let (temp, _paths, owner) = fixture();
        let source = temp.path().join("source");
        std::fs::write(&source, "version = 0").expect("source");
        let link = temp.path().join("link");
        symlink(&source, &link).expect("symlink");
        assert!(read_import(&link, Some(owner)).is_err());
        assert!(read_import(temp.path(), Some(owner)).is_err());
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "create a FIFO only inside a temporary test directory"
    )]
    fn fifo_import_is_rejected_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let (temp, _paths, owner) = fixture();
        let source = temp.path().join("fifo");
        let name = std::ffi::CString::new(source.as_os_str().as_bytes()).expect("path");
        // SAFETY: name is a live NUL-terminated path owned by this test.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(
            read_import(&source, Some(owner))
                .expect_err("FIFO")
                .to_string()
                .contains("regular file")
        );
    }

    #[test]
    fn untrusted_directories_are_rejected_without_chmod() {
        let (temp, paths, owner) = fixture();
        let actual = temp.path().join("actual");
        std::fs::create_dir(&actual).expect("directory");
        symlink(&actual, paths.config_dir()).expect("symlink");
        assert!(prepare_config(&paths, None, None, owner).is_err());
        std::fs::remove_file(paths.config_dir()).expect("unlink");
        std::fs::create_dir(paths.config_dir()).expect("directory");
        for mode in [0o770, 0o707] {
            std::fs::set_permissions(paths.config_dir(), std::fs::Permissions::from_mode(mode))
                .expect("mode");
            assert!(prepare_config(&paths, None, None, owner).is_err());
            assert_eq!(
                std::fs::metadata(paths.config_dir())
                    .expect("metadata")
                    .mode()
                    & 0o777,
                mode
            );
        }
        std::fs::set_permissions(paths.config_dir(), std::fs::Permissions::from_mode(0o700))
            .expect("mode");
        assert!(prepare_config(&paths, None, None, owner ^ 1).is_err());
    }

    #[test]
    fn existing_machine_symlink_is_not_followed() {
        let (temp, paths, owner) = fixture();
        prepare_config(&paths, None, None, owner).expect("directories");
        let secret = temp.path().join("secret");
        std::fs::write(&secret, "do-not-touch").expect("secret");
        symlink(&secret, paths.config_file()).expect("symlink");
        assert!(prepare_config(&paths, None, None, owner).is_err());
        assert_eq!(
            std::fs::read_to_string(secret).expect("secret"),
            "do-not-touch"
        );
    }
}
