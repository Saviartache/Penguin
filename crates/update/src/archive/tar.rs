//! Чтение tar.gz: заголовки ustar и длинные имена GNU.

use std::io::Read;

use flate2::read::GzDecoder;

use super::extract::MAX_MEMBER;
use super::path::normalize;
use crate::error::{UpdateError, UpdateResult};

const BLOCK: usize = 512;

fn corrupt(what: &str) -> UpdateError {
    UpdateError::Archive(format!("tar: {what}"))
}

/// Достаёт файл `member` (имя уже нормализовано); `None` — его нет.
///
/// Имена всех записей проверяются, а не только нужной.
pub(super) fn read_member(gz: &[u8], member: &str) -> UpdateResult<Option<Vec<u8>>> {
    let mut tar = Vec::new();
    // Распакованное больше предела — не наш архив: ядро поставки одно, около десятков мегабайт.
    GzDecoder::new(gz)
        .take(MAX_MEMBER * 2)
        .read_to_end(&mut tar)
        .map_err(|err| corrupt(&err.to_string()))?;

    let mut offset = 0;
    let mut long_name: Option<String> = None;
    let mut found = None;
    while let Some(header) = tar.get(offset..offset + BLOCK) {
        if header.iter().all(|&byte| byte == 0) {
            break;
        }
        let size = octal(&header[124..136])?;
        let data_start = offset + BLOCK;
        let data = tar
            .get(
                data_start
                    ..data_start
                        .checked_add(size)
                        .ok_or_else(|| corrupt("размер"))?,
            )
            .ok_or_else(|| corrupt("обрыв"))?;
        offset = data_start + size.next_multiple_of(BLOCK);

        let kind = header[156];
        if kind == b'L' {
            long_name = Some(c_string(data));
            continue;
        }
        let name = normalize(&long_name.take().unwrap_or_else(|| entry_name(header)))?;
        if name == member && matches!(kind, b'0' | 0) && found.is_none() {
            found = Some(data.to_vec());
        }
    }
    Ok(found)
}

/// Имя записи ustar: префикс (`345..500`) и имя (`0..100`).
fn entry_name(header: &[u8]) -> String {
    let name = c_string(&header[..100]);
    let prefix = if &header[257..262] == b"ustar" {
        c_string(&header[345..500])
    } else {
        String::new()
    };
    if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    }
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn octal(field: &[u8]) -> UpdateResult<usize> {
    let text = c_string(field);
    let digits = text.trim_matches(|c: char| c == ' ' || c == '\0');
    if digits.is_empty() {
        return Ok(0);
    }
    usize::from_str_radix(digits, 8).map_err(|_| corrupt("размер"))
}

#[cfg(test)]
pub(super) mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    /// Собирает tar.gz: `(тип, имя, данные)`.
    pub(in crate::archive) fn build(entries: &[(u8, &str, &[u8])]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (kind, name, data) in entries {
            let mut header = [0u8; BLOCK];
            let short = name.len().min(100);
            header[..short].copy_from_slice(&name.as_bytes()[..short]);
            header[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
            header[156] = *kind;
            header[257..262].copy_from_slice(b"ustar");
            tar.extend(header);
            tar.extend(*data);
            tar.resize(tar.len().next_multiple_of(BLOCK), 0);
        }
        tar.extend([0u8; BLOCK * 2]);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar).expect("сжатие");
        encoder.finish().expect("сжатие")
    }

    #[test]
    fn a_member_is_found_behind_the_dot_prefix_tar_adds() {
        let body = b"binary".repeat(300);
        let archive = build(&[
            (b'5', "./", b""),
            (b'0', "./penguin.png", b"png"),
            (b'0', "./penguin", &body),
        ]);

        assert_eq!(read_member(&archive, "penguin").expect("tar"), Some(body));
        assert_eq!(read_member(&archive, "absent").expect("tar"), None);
    }

    #[test]
    fn gnu_long_names_are_followed() {
        let long = format!("dir/{}/penguin", "x".repeat(150));
        let archive = build(&[
            (b'L', "././@LongLink", format!("{long}\0").as_bytes()),
            (b'0', "truncated", b"payload"),
        ]);

        assert_eq!(
            read_member(&archive, &long).expect("tar"),
            Some(b"payload".to_vec())
        );
    }

    #[test]
    fn a_climbing_entry_poisons_the_whole_archive() {
        let archive = build(&[(b'0', "penguin", b"ok"), (b'0', "../../evil", b"x")]);

        let err = read_member(&archive, "penguin").expect_err("zip-slip");
        assert!(matches!(err, UpdateError::UnsafePath(_)), "{err}");
    }

    #[test]
    fn links_are_never_taken_for_the_file() {
        let archive = build(&[(b'2', "penguin", b"")]);
        assert_eq!(read_member(&archive, "penguin").expect("tar"), None);
    }

    #[test]
    fn a_lying_size_errors_instead_of_panicking() {
        let mut tar = vec![0u8; BLOCK];
        tar[..7].copy_from_slice(b"penguin");
        tar[124..135].copy_from_slice(b"77777777777");
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar).expect("сжатие");
        let archive = encoder.finish().expect("сжатие");

        assert!(read_member(&archive, "penguin").is_err());
    }
}
