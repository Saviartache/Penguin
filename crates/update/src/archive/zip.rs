//! Чтение zip по центральному каталогу: stored и deflate, без zip64 и шифрования.

use std::io::Read;

use flate2::read::DeflateDecoder;

use super::extract::MAX_MEMBER;
use super::path::normalize;
use crate::error::{UpdateError, UpdateResult};

const END_SIGNATURE: u32 = 0x0605_4b50;
const ENTRY_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
/// Запись конца каталога: 22 байта и комментарий до 65535.
const END_SEARCH: usize = 22 + 65535;

fn corrupt(what: &str) -> UpdateError {
    UpdateError::Archive(format!("zip: {what}"))
}

fn u16_at(bytes: &[u8], offset: usize) -> UpdateResult<usize> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| corrupt("обрыв"))?;
    Ok(usize::from(u16::from_le_bytes([raw[0], raw[1]])))
}

fn u32_at(bytes: &[u8], offset: usize) -> UpdateResult<u32> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| corrupt("обрыв"))?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn u32_usize(bytes: &[u8], offset: usize) -> UpdateResult<usize> {
    usize::try_from(u32_at(bytes, offset)?).map_err(|_| corrupt("размер"))
}

/// Достаёт файл `member` (имя уже нормализовано); `None` — его нет.
///
/// Имена всех записей проверяются, а не только нужной.
pub(super) fn read_member(bytes: &[u8], member: &str) -> UpdateResult<Option<Vec<u8>>> {
    let end = find_end(bytes)?;
    let count = u16_at(bytes, end + 10)?;
    let mut offset = u32_usize(bytes, end + 16)?;
    if count == 0xFFFF || offset == 0xFFFF_FFFF {
        return Err(corrupt("zip64 не поддерживается"));
    }

    let mut found = None;
    for _ in 0..count {
        if u32_at(bytes, offset)? != ENTRY_SIGNATURE {
            return Err(corrupt("битый каталог"));
        }
        let flags = u16_at(bytes, offset + 8)?;
        let method = u16_at(bytes, offset + 10)?;
        let compressed = u32_usize(bytes, offset + 20)?;
        let size = u32_usize(bytes, offset + 24)?;
        let name_len = u16_at(bytes, offset + 28)?;
        let extra_len = u16_at(bytes, offset + 30)?;
        let comment_len = u16_at(bytes, offset + 32)?;
        let local = u32_usize(bytes, offset + 42)?;
        let raw_name = bytes
            .get(offset + 46..offset + 46 + name_len)
            .ok_or_else(|| corrupt("обрыв"))?;
        offset += 46 + name_len + extra_len + comment_len;

        let name = normalize(&String::from_utf8_lossy(raw_name))?;
        if name == member && found.is_none() {
            if flags & 1 != 0 {
                return Err(corrupt("запись зашифрована"));
            }
            found = Some((method, compressed, size, local));
        }
    }

    found
        .map(|(method, compressed, size, local)| read_entry(bytes, method, compressed, size, local))
        .transpose()
}

/// Конец каталога ищется с хвоста: после него бывает комментарий.
fn find_end(bytes: &[u8]) -> UpdateResult<usize> {
    let start = bytes.len().saturating_sub(END_SEARCH);
    (start..=bytes.len().saturating_sub(22))
        .rev()
        .find(|&at| u32_at(bytes, at).is_ok_and(|signature| signature == END_SIGNATURE))
        .ok_or_else(|| corrupt("нет конца каталога"))
}

fn read_entry(
    bytes: &[u8],
    method: usize,
    compressed: usize,
    size: usize,
    local: usize,
) -> UpdateResult<Vec<u8>> {
    if size as u64 > MAX_MEMBER {
        return Err(UpdateError::TooLarge { limit: MAX_MEMBER });
    }
    if u32_at(bytes, local)? != LOCAL_SIGNATURE {
        return Err(corrupt("битая запись"));
    }
    // Длины имени и дополнения в локальном заголовке могут отличаться от каталожных.
    let start = local + 30 + u16_at(bytes, local + 26)? + u16_at(bytes, local + 28)?;
    let data = bytes
        .get(start..start + compressed)
        .ok_or_else(|| corrupt("обрыв"))?;

    let mut out = Vec::with_capacity(size);
    match method {
        0 => out.extend_from_slice(data),
        8 => {
            DeflateDecoder::new(data)
                .take(MAX_MEMBER + 1)
                .read_to_end(&mut out)
                .map_err(|err| corrupt(&err.to_string()))?;
        }
        other => return Err(corrupt(&format!("метод сжатия {other}"))),
    }
    if out.len() != size {
        return Err(corrupt("размер не сошёлся"));
    }
    Ok(out)
}

#[cfg(test)]
pub(super) mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    use super::*;

    /// Собирает zip: `(имя, данные, сжимать)`.
    pub(in crate::archive) fn build(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut directory = Vec::new();
        for (name, data, deflate) in entries {
            let packed = if *deflate {
                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(data).expect("сжатие");
                encoder.finish().expect("сжатие")
            } else {
                data.to_vec()
            };
            let method: u16 = if *deflate { 8 } else { 0 };
            let offset = out.len() as u32;
            let name_len = name.len() as u16;

            out.extend(LOCAL_SIGNATURE.to_le_bytes());
            out.extend([20, 0, 0, 0]);
            out.extend(method.to_le_bytes());
            out.extend([0; 8]);
            out.extend((packed.len() as u32).to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend(name_len.to_le_bytes());
            out.extend([0, 0]);
            out.extend(name.as_bytes());
            out.extend(&packed);

            directory.extend(ENTRY_SIGNATURE.to_le_bytes());
            directory.extend([20, 0, 20, 0, 0, 0]);
            directory.extend(method.to_le_bytes());
            directory.extend([0; 8]);
            directory.extend((packed.len() as u32).to_le_bytes());
            directory.extend((data.len() as u32).to_le_bytes());
            directory.extend(name_len.to_le_bytes());
            directory.extend([0; 12]);
            directory.extend(offset.to_le_bytes());
            directory.extend(name.as_bytes());
        }
        let directory_offset = out.len() as u32;
        out.extend(&directory);
        out.extend(END_SIGNATURE.to_le_bytes());
        out.extend([0; 4]);
        out.extend((entries.len() as u16).to_le_bytes());
        out.extend((entries.len() as u16).to_le_bytes());
        out.extend((directory.len() as u32).to_le_bytes());
        out.extend(directory_offset.to_le_bytes());
        out.extend([0, 0]);
        out
    }

    #[test]
    fn stored_and_deflated_entries_are_read() {
        let body = b"penguin ".repeat(100);
        let archive = build(&[("a.txt", b"first", false), ("dir/penguin", &body, true)]);

        assert_eq!(
            read_member(&archive, "a.txt").expect("zip"),
            Some(b"first".to_vec())
        );
        assert_eq!(
            read_member(&archive, "dir/penguin").expect("zip"),
            Some(body)
        );
        assert_eq!(read_member(&archive, "missing").expect("zip"), None);
    }

    #[test]
    fn a_climbing_entry_poisons_the_whole_archive() {
        let archive = build(&[("penguin", b"ok", false), ("../../evil", b"x", false)]);

        let err = read_member(&archive, "penguin").expect_err("zip-slip");
        assert!(matches!(err, UpdateError::UnsafePath(_)), "{err}");
    }

    #[test]
    fn truncated_archives_error_instead_of_panicking() {
        let archive = build(&[("penguin", b"data", true)]);
        for cut in 0..archive.len() {
            let _ = read_member(&archive[..cut], "penguin");
        }
    }

    #[test]
    fn a_lying_size_is_refused() {
        let mut archive = build(&[("penguin", b"data", false)]);
        // Размер в каталоге: после сигнатуры, версий, флагов, метода, времени и CRC, сжатого размера.
        let directory = archive
            .windows(4)
            .position(|window| window == ENTRY_SIGNATURE.to_le_bytes())
            .expect("каталог");
        archive[directory + 24] = 9;

        assert!(read_member(&archive, "penguin").is_err());
    }
}
