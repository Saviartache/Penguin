//! Блок полей: префикс и представления (RFC 9204, §4.5).
//!
//! Динамической таблицы здесь нет ни в одну сторону. Свою ёмкость клиент
//! объявляет нулевой (умолчание, RFC 9204, §5), поэтому сервер обязан
//! кодировать без ссылок на неё; сам клиент на неё тоже не ссылается.
//! Значит, у каждого блока `Required Insert Count = 0`, а потоки кодировщика
//! и декодировщика пусты.

use super::QpackError;
use super::primitive::{decode_int, decode_str, encode_int, encode_str};
use super::static_table::{self, Match};

/// Поле: имя и значение как байты.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// Имя — строчными буквами (RFC 9114, §4.2).
    pub name: Vec<u8>,
    /// Значение.
    pub value: Vec<u8>,
}

/// Сколько поле весит для предела `SETTINGS_MAX_FIELD_SECTION_SIZE`:
/// имя, значение и 32 байта сверху (RFC 9114, §4.2.2).
pub fn field_size(name: &[u8], value: &[u8]) -> usize {
    name.len() + value.len() + 32
}

/// Кодирует блок полей.
pub fn encode<'a>(fields: impl IntoIterator<Item = (&'a [u8], &'a [u8])>) -> Vec<u8> {
    // Required Insert Count = 0, знак и Delta Base = 0.
    let mut out = vec![0x00, 0x00];
    for (name, value) in fields {
        match static_table::find(name, value) {
            // Индексированная строка, T = 1 (§4.5.2).
            Some(Match::Full(index)) => encode_int(index, 6, 0b1100_0000, &mut out),
            // Литерал со ссылкой на имя, N = 0, T = 1 (§4.5.4).
            Some(Match::Name(index)) => {
                encode_int(index, 4, 0b0101_0000, &mut out);
                encode_str(value, 7, 0, &mut out);
            }
            // Литерал с литеральным именем, N = 0 (§4.5.6).
            None => {
                encode_str(name, 3, 0b0010_0000, &mut out);
                encode_str(value, 7, 0, &mut out);
            }
        }
    }
    out
}

/// Разбирает блок полей. `limit` — предел размера по [`field_size`].
pub fn decode(src: &[u8], limit: usize) -> Result<Vec<Field>, QpackError> {
    let (required_insert_count, used) = decode_int(src, 8)?;
    if required_insert_count != 0 {
        return Err(QpackError::Dynamic);
    }
    let rest = &src[used..];
    let sign = rest.first().ok_or(QpackError::Truncated)? & 0x80 != 0;
    // При нулевом Required Insert Count знак 1 даёт отрицательную базу
    // (§4.5.1.2); саму Delta Base без таблицы читать незачем.
    if sign {
        return Err(QpackError::Dynamic);
    }
    let (_, used) = decode_int(rest, 7)?;

    let mut src = &rest[used..];
    let mut fields = Vec::new();
    let mut size = 0usize;
    while !src.is_empty() {
        let (field, used) = decode_line(src)?;
        size += field_size(&field.name, &field.value);
        if size > limit {
            return Err(QpackError::TooLarge(limit));
        }
        fields.push(field);
        src = &src[used..];
    }
    Ok(fields)
}

/// Разбирает одно представление. Возвращает поле и число прочитанных байт.
fn decode_line(src: &[u8]) -> Result<(Field, usize), QpackError> {
    let first = src[0];
    if first & 0b1000_0000 != 0 {
        // Индексированная строка (§4.5.2); T = 0 — динамическая таблица.
        if first & 0b0100_0000 == 0 {
            return Err(QpackError::Dynamic);
        }
        let (index, used) = decode_int(src, 6)?;
        let (name, value) = static_entry(index)?;
        return Ok((field(name.as_bytes(), value.as_bytes().to_vec()), used));
    }
    if first & 0b0100_0000 != 0 {
        // Литерал со ссылкой на имя (§4.5.4).
        if first & 0b0001_0000 == 0 {
            return Err(QpackError::Dynamic);
        }
        let (index, used) = decode_int(src, 4)?;
        let (name, _) = static_entry(index)?;
        let (value, value_used) = decode_str(&src[used..], 7)?;
        return Ok((field(name.as_bytes(), value), used + value_used));
    }
    if first & 0b0010_0000 != 0 {
        // Литерал с литеральным именем (§4.5.6).
        let (name, used) = decode_str(src, 3)?;
        let (value, value_used) = decode_str(&src[used..], 7)?;
        return Ok((Field { name, value }, used + value_used));
    }
    // `0001` и `0000` — ссылки за базу (§4.5.3, §4.5.5): только динамика.
    Err(QpackError::Dynamic)
}

fn static_entry(index: u64) -> Result<(&'static str, &'static str), QpackError> {
    static_table::get(index).ok_or(QpackError::StaticIndex(index))
}

fn field(name: &[u8], value: Vec<u8>) -> Field {
    Field {
        name: name.to_vec(),
        value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_LIMIT: usize = usize::MAX;

    #[test]
    fn the_rfc_9204_static_example_decodes() {
        // RFC 9204, приложение B.1: `:path=/index.html` ссылкой на имя.
        let wire = [
            0x00, 0x00, 0x51, 0x0b, 0x2f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d,
            0x6c,
        ];
        let fields = decode(&wire, NO_LIMIT).expect("разбирается");
        assert_eq!(fields, [field(b":path", b"/index.html".to_vec())]);
    }

    #[test]
    fn a_dynamic_reference_is_refused() {
        // RFC 9204, приложение B.2, поток 4: Required Insert Count = 2.
        let wire = [0x03, 0x81, 0x10, 0x11];
        assert_eq!(decode(&wire, NO_LIMIT), Err(QpackError::Dynamic));
        // Индекс с T = 0.
        assert_eq!(
            decode(&[0x00, 0x00, 0x80], NO_LIMIT),
            Err(QpackError::Dynamic)
        );
    }

    #[test]
    fn a_connect_request_round_trips() {
        // Круговой прогон: внешний вектор на кодирование с Хаффманом в
        // RFC 9204 нет, разбор сверен выше на B.1.
        let fields: [(&[u8], &[u8]); 4] = [
            (b":method", b"CONNECT"),
            (b":authority", b"example.com:443"),
            (b"proxy-authorization", b"Basic dXNlcjpwYXNz"),
            (b"padding", b"~~~~~~~~~~~~~~~~"),
        ];
        let wire = encode(fields);
        // `:method: CONNECT` — один байт: индекс 15 статической таблицы.
        assert_eq!(&wire[..3], &[0x00, 0x00, 0xcf]);

        let decoded = decode(&wire, NO_LIMIT).expect("разбирается");
        let expected: Vec<Field> = fields
            .iter()
            .map(|(name, value)| field(name, value.to_vec()))
            .collect();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn an_unknown_static_index_is_refused() {
        // Индекс 99 — за концом таблицы.
        assert_eq!(
            decode(&[0x00, 0x00, 0xff, 0x24], NO_LIMIT),
            Err(QpackError::StaticIndex(99))
        );
    }

    #[test]
    fn the_size_limit_is_enforced() {
        let wire = encode([(&b"x-a"[..], &b"1"[..])]);
        assert!(decode(&wire, 36).is_ok());
        assert_eq!(decode(&wire, 35), Err(QpackError::TooLarge(35)));
    }
}
