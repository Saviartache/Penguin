//! Доменные имена: метки с длиной и указатели сжатия.

use super::header::truncated;
use crate::error::{DnsError, DnsResult};

/// Наибольшая длина имени в текстовом виде.
const MAX_NAME: usize = 253;
/// Наибольшая длина метки.
const MAX_LABEL: usize = 63;

fn bad(what: &str) -> DnsError {
    DnsError::Malformed(format!("имя: {what}"))
}

/// Читает имя с позиции `start` в нижнем регистре и без завершающей точки.
///
/// Возвращает позицию сразу за именем в потоке. Указатель обязан вести назад
/// (так цепочки указателей конечны), а длина имени ограничена (так конечны
/// и циклы через метки).
pub(super) fn read(msg: &[u8], start: usize, out: &mut String) -> DnsResult<usize> {
    let mut pos = start;
    let mut end = None;
    loop {
        let len = *msg.get(pos).ok_or_else(truncated)?;
        match len & 0xC0 {
            0 if len == 0 => return Ok(end.unwrap_or(pos + 1)),
            0 => {
                let len = usize::from(len);
                let label = msg.get(pos + 1..pos + 1 + len).ok_or_else(truncated)?;
                if !out.is_empty() {
                    out.push('.');
                }
                for &byte in label {
                    if !(0x21..=0x7E).contains(&byte) || byte == b'.' {
                        return Err(bad("недопустимый байт в метке"));
                    }
                    out.push(char::from(byte.to_ascii_lowercase()));
                }
                if out.len() > MAX_NAME {
                    return Err(bad("слишком длинное"));
                }
                pos += 1 + len;
            }
            0xC0 => {
                let low = *msg.get(pos + 1).ok_or_else(truncated)?;
                let target = usize::from(len & 0x3F) << 8 | usize::from(low);
                if target >= pos {
                    return Err(bad("указатель ведёт вперёд"));
                }
                end.get_or_insert(pos + 2);
                pos = target;
            }
            _ => return Err(bad("неизвестный тип метки")),
        }
    }
}

/// Пропускает имя, не разбирая его; возвращает позицию за ним.
pub(super) fn skip(msg: &[u8], start: usize) -> DnsResult<usize> {
    let mut pos = start;
    loop {
        let len = *msg.get(pos).ok_or_else(truncated)?;
        match len & 0xC0 {
            0 if len == 0 => return Ok(pos + 1),
            0 => pos += 1 + usize::from(len),
            0xC0 if pos + 2 <= msg.len() => return Ok(pos + 2),
            0xC0 => return Err(truncated()),
            _ => return Err(bad("неизвестный тип метки")),
        }
    }
}

/// Дописывает имя без сжатия.
pub(super) fn write(out: &mut Vec<u8>, name: &str) -> DnsResult<()> {
    let name = name.trim_end_matches('.');
    if name.len() > MAX_NAME {
        return Err(bad("слишком длинное"));
    }
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > MAX_LABEL || !label.is_ascii() {
                return Err(bad("недопустимая метка"));
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(msg: &[u8], start: usize) -> DnsResult<(String, usize)> {
        let mut name = String::new();
        let next = read(msg, start, &mut name)?;
        Ok((name, next))
    }

    #[test]
    fn plain_name_is_lowercased() {
        let msg = b"\x07EXAMPLE\x03Com\x00tail";
        assert_eq!(
            read_all(msg, 0).expect("имя"),
            ("example.com".to_owned(), 13)
        );
        assert_eq!(skip(msg, 0).expect("пропуск"), 13);
    }

    #[test]
    fn root_is_empty() {
        assert_eq!(read_all(&[0], 0).expect("корень"), (String::new(), 1));
    }

    #[test]
    fn compression_pointer_is_followed_and_end_is_after_pointer() {
        // [0] example.com, [13] www + указатель на 0, [19] хвост
        let mut msg = b"\x07example\x03com\x00\x03www\xC0\x00".to_vec();
        msg.push(0x7F);
        assert_eq!(
            read_all(&msg, 13).expect("имя"),
            ("www.example.com".to_owned(), 19)
        );
        assert_eq!(skip(&msg, 13).expect("пропуск"), 19);
    }

    #[test]
    fn pointer_to_itself_is_rejected() {
        assert!(read_all(&[0xC0, 0x00], 0).is_err());
    }

    #[test]
    fn forward_pointer_is_rejected() {
        assert!(read_all(&[0xC0, 0x02, 0x00], 0).is_err());
    }

    #[test]
    fn cycle_through_labels_is_bounded() {
        // [0] 'a' [2] указатель на 0: бесконечное «a.a.a...»
        let msg = [0x01, b'a', 0xC0, 0x00];
        assert!(read_all(&msg, 2).is_err());
    }

    #[test]
    fn pointer_chain_goes_down_and_ends() {
        let msg = [0x01, b'a', 0x00, 0xC0, 0x00, 0xC0, 0x03];
        assert_eq!(read_all(&msg, 5).expect("цепочка"), ("a".to_owned(), 7));
    }

    #[test]
    fn truncated_inputs_are_rejected() {
        assert!(read_all(&[0x05, b'a', b'b'], 0).is_err());
        assert!(read_all(&[0xC0], 0).is_err());
        assert!(read_all(&[], 0).is_err());
        assert!(skip(&[0x03, b'a'], 0).is_err());
        assert!(skip(&[0xC0], 0).is_err());
    }

    #[test]
    fn reserved_label_types_are_rejected() {
        assert!(read_all(&[0x40, 0x00], 0).is_err());
        assert!(read_all(&[0x80, 0x00], 0).is_err());
        assert!(skip(&[0x80, 0x00], 0).is_err());
    }

    #[test]
    fn name_over_the_limit_is_rejected() {
        let mut msg = Vec::new();
        for _ in 0..5 {
            msg.push(62);
            msg.extend(std::iter::repeat_n(b'a', 62));
        }
        msg.push(0);
        assert!(read_all(&msg, 0).is_err());
    }

    #[test]
    fn write_matches_the_wire_form() {
        let mut out = Vec::new();
        write(&mut out, "Example.com.").expect("пишется");
        assert_eq!(out, b"\x07Example\x03com\x00");

        let mut root = Vec::new();
        write(&mut root, ".").expect("корень");
        assert_eq!(root, [0]);
    }

    #[test]
    fn write_rejects_bad_names() {
        let mut out = Vec::new();
        assert!(write(&mut out, "a..b").is_err());
        assert!(write(&mut out, &"a".repeat(64)).is_err());
        assert!(write(&mut out, "пример.рф").is_err());
        assert!(write(&mut out, &format!("{}.com", "a.".repeat(130))).is_err());
    }
}
