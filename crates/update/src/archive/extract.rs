//! Выбор читателя по формату поставки.

use super::{path::normalize, tar, zip};
use crate::error::{UpdateError, UpdateResult};
use crate::target::Format;

/// Предел одного файла из архива: исполняемый файл — десятки мегабайт.
pub(super) const MAX_MEMBER: u64 = 256 * 1024 * 1024;

/// Достаёт из архива файл `member`; нет его — [`UpdateError::MemberMissing`].
pub(crate) fn extract_member(
    format: Format,
    archive: &[u8],
    member: &str,
) -> UpdateResult<Vec<u8>> {
    let member = normalize(member)?;
    let found = match format {
        Format::Zip => zip::read_member(archive, &member)?,
        Format::TarGz => tar::read_member(archive, &member)?,
    };
    found.ok_or(UpdateError::MemberMissing(member))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_and_tar_give_the_same_file() {
        let zip = zip::tests::build(&[("Penguin.app/Contents/MacOS/penguin", b"bin", true)]);
        let tgz = tar::tests::build(&[(b'0', "./penguin", b"bin")]);

        assert_eq!(
            extract_member(Format::Zip, &zip, "Penguin.app/Contents/MacOS/penguin").expect("zip"),
            b"bin"
        );
        assert_eq!(
            extract_member(Format::TarGz, &tgz, "penguin").expect("tar"),
            b"bin"
        );
    }

    #[test]
    fn a_missing_member_is_named() {
        let zip = zip::tests::build(&[("other", b"x", false)]);
        let err = extract_member(Format::Zip, &zip, "penguin.exe").expect_err("нет файла");
        assert!(matches!(err, UpdateError::MemberMissing(name) if name == "penguin.exe"));
    }

    #[test]
    fn not_an_archive_is_an_error() {
        assert!(extract_member(Format::Zip, b"<html>not found</html>", "penguin").is_err());
        assert!(extract_member(Format::TarGz, b"<html>not found</html>", "penguin").is_err());
    }
}
