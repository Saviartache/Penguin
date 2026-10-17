//! Порядок установки: сверить, достать, подменить. Скачанное не запускается никогда.

use std::path::Path;

use crate::archive::extract_member;
use crate::checksum;
use crate::error::UpdateResult;
use crate::release::Available;
use crate::replace::replace_executable;
use crate::target::Target;

/// Проверяет архив по `SHA256SUMS`, достаёт исполняемый файл и кладёт его на место `executable`.
///
/// Любой отказ до подмены оставляет прежний файл нетронутым.
pub fn install_archive(
    archive: &[u8],
    sums: &str,
    available: &Available,
    target: &Target,
    executable: &Path,
) -> UpdateResult<()> {
    checksum::verify(archive, sums, &available.archive_name)?;
    let new = extract_member(target.format, archive, target.member)?;
    replace_executable(executable, &new)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;
    use crate::error::UpdateError;

    fn tar_gz(body: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..9].copy_from_slice(b"./penguin");
        header[124..135].copy_from_slice(format!("{:011o}", body.len()).as_bytes());
        header[156] = b'0';
        let mut tar = header.to_vec();
        tar.extend(body);
        tar.resize(tar.len().next_multiple_of(512) + 1024, 0);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar).expect("сжатие");
        encoder.finish().expect("сжатие")
    }

    fn available() -> Available {
        Available {
            version: "0.8.0".into(),
            page_url: String::new(),
            archive_name: "penguin-0.8.0-linux-x64.tar.gz".into(),
            archive_url: String::new(),
            sums_url: String::new(),
        }
    }

    fn directory(name: &str) -> std::path::PathBuf {
        let directory =
            std::env::temp_dir().join(format!("penguin-flow-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("каталог");
        directory
    }

    #[test]
    fn a_verified_archive_replaces_the_executable() {
        let directory = directory("ok");
        let executable = directory.join("penguin");
        std::fs::write(&executable, b"old").expect("старый");
        let archive = tar_gz(b"new build");
        let sums = format!(
            "{}  penguin-0.8.0-linux-x64.tar.gz\n",
            checksum::sha256_hex(&archive)
        );
        let target = Target::of("linux", "x86_64").expect("поставка");

        install_archive(&archive, &sums, &available(), &target, &executable).expect("установка");

        assert_eq!(std::fs::read(&executable).expect("файл"), b"new build");
        std::fs::remove_dir_all(&directory).expect("уборка");
    }

    #[test]
    fn a_hash_mismatch_refuses_and_leaves_the_old_file() {
        let directory = directory("mismatch");
        let executable = directory.join("penguin");
        std::fs::write(&executable, b"old").expect("старый");
        let archive = tar_gz(b"tampered");
        let sums = format!("{}  penguin-0.8.0-linux-x64.tar.gz\n", "0".repeat(64));
        let target = Target::of("linux", "x86_64").expect("поставка");

        let err = install_archive(&archive, &sums, &available(), &target, &executable)
            .expect_err("подмена");

        assert!(matches!(err, UpdateError::ChecksumMismatch { .. }), "{err}");
        assert_eq!(std::fs::read(&executable).expect("файл"), b"old");
        std::fs::remove_dir_all(&directory).expect("уборка");
    }

    #[test]
    fn an_archive_missing_from_the_sums_is_refused() {
        let directory = directory("unlisted");
        let executable = directory.join("penguin");
        std::fs::write(&executable, b"old").expect("старый");
        let target = Target::of("linux", "x86_64").expect("поставка");

        let err = install_archive(&tar_gz(b"x"), "", &available(), &target, &executable)
            .expect_err("нет суммы");

        assert!(matches!(err, UpdateError::MissingChecksum(_)), "{err}");
        assert_eq!(std::fs::read(&executable).expect("файл"), b"old");
        std::fs::remove_dir_all(&directory).expect("уборка");
    }
}
