//! `SHA256SUMS` (формат `sha256sum`) и сверка архива.

use std::fmt::Write;

use sha2::{Digest, Sha256};

use crate::error::{UpdateError, UpdateResult};

/// SHA-256 в нижнем регистре, шестнадцатеричной строкой.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Сумма файла `name` из текста `SHA256SUMS`: строки вида `<hex>  <имя>` или `<hex> *<имя>`.
pub(crate) fn expected_for(sums: &str, name: &str) -> UpdateResult<String> {
    sums.lines()
        .filter_map(|line| {
            let (hash, file) = line.split_once(char::is_whitespace)?;
            let file = file.trim_start().trim_start_matches('*');
            let valid = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
            (valid && file == name).then(|| hash.to_ascii_lowercase())
        })
        .next()
        .ok_or_else(|| UpdateError::MissingChecksum(name.to_owned()))
}

/// Сверяет архив с суммой из `SHA256SUMS`; несовпадение — отказ.
pub(crate) fn verify(bytes: &[u8], sums: &str, name: &str) -> UpdateResult<()> {
    let expected = expected_for(sums, name)?;
    let actual = sha256_hex(bytes);
    if actual != expected {
        return Err(UpdateError::ChecksumMismatch { expected, actual });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // `printf abc | sha256sum`
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn the_known_vector_matches() {
        assert_eq!(sha256_hex(b"abc"), ABC);
    }

    #[test]
    fn both_sha256sum_spellings_are_read() {
        let other = "0".repeat(64);
        let sums = format!(
            "{other}  penguin-0.8.0-linux-x64.tar.gz\n{ABC} *penguin-0.8.0-macos-x64.zip\n\n"
        );

        assert_eq!(
            expected_for(&sums, "penguin-0.8.0-linux-x64.tar.gz").expect("есть"),
            other
        );
        assert_eq!(
            expected_for(&sums, "penguin-0.8.0-macos-x64.zip").expect("есть"),
            ABC
        );
    }

    #[test]
    fn an_unlisted_or_malformed_line_is_missing() {
        let sums = format!("{ABC}  a.zip\nnot-a-hash  b.zip\n{ABC}  c.zip.sig\n");

        assert!(matches!(
            expected_for(&sums, "b.zip"),
            Err(UpdateError::MissingChecksum(_))
        ));
        assert!(matches!(
            expected_for(&sums, "c.zip"),
            Err(UpdateError::MissingChecksum(_))
        ));
        assert!(matches!(
            expected_for("", "a.zip"),
            Err(UpdateError::MissingChecksum(_))
        ));
    }

    #[test]
    fn upper_case_sums_are_accepted() {
        let sums = format!("{}  a.zip\n", ABC.to_ascii_uppercase());
        verify(b"abc", &sums, "a.zip").expect("регистр не важен");
    }

    #[test]
    fn a_changed_archive_is_refused() {
        let sums = format!("{ABC}  a.zip\n");

        verify(b"abc", &sums, "a.zip").expect("тот же файл");
        let err = verify(b"abd", &sums, "a.zip").expect_err("подмена");
        assert!(matches!(err, UpdateError::ChecksumMismatch { .. }), "{err}");
    }
}
