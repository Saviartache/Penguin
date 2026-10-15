//! Кадр `SETTINGS` (RFC 9114, §7.2.4) и настройки расширений.

use bytes::Bytes;

use super::code::{H3_FRAME_ERROR, H3_SETTINGS_ERROR};
use super::error::{H3Error, H3Result};
use crate::varint;

/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC 9204, §5).
pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114, §7.2.4.1).
pub const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
/// `SETTINGS_QPACK_BLOCKED_STREAMS` (RFC 9204, §5).
pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 9220, §3).
pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
/// `SETTINGS_H3_DATAGRAM` (RFC 9297, §2.1.1).
pub const H3_DATAGRAM: u64 = 0x33;

/// Что объявил собеседник.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// Предел блока полей; `None` — без предела.
    pub max_field_section_size: Option<u64>,
    /// Ёмкость динамической таблицы QPACK, которую собеседник готов принять.
    pub qpack_max_table_capacity: u64,
    /// Сервер принимает расширенный `CONNECT` с `:protocol`.
    pub enable_connect_protocol: bool,
    /// Собеседник принимает датаграммы HTTP/3.
    pub h3_datagram: bool,
}

/// Собирает содержимое своего кадра `SETTINGS`.
///
/// `grease` — идентификатор зарезервированной настройки вида
/// `0x1f * N + 0x21`: RFC 9114, §7.2.4.1 советует слать хотя бы одну, чтобы
/// собеседники не разучились пропускать незнакомые.
pub fn encode(max_field_section_size: u64, h3_datagram: bool, grease: (u64, u64)) -> Bytes {
    let mut out = Vec::new();
    varint::encode(MAX_FIELD_SECTION_SIZE, &mut out);
    varint::encode(max_field_section_size, &mut out);
    if h3_datagram {
        varint::encode(H3_DATAGRAM, &mut out);
        varint::encode(1, &mut out);
    }
    varint::encode(grease.0, &mut out);
    varint::encode(grease.1, &mut out);
    Bytes::from(out)
}

/// Идентификатор зарезервированной настройки с номером `n`.
pub fn grease_id(n: u64) -> u64 {
    0x1f * n + 0x21
}

/// Разбирает содержимое кадра `SETTINGS` собеседника.
pub fn decode(mut payload: &[u8]) -> H3Result<Settings> {
    let mut settings = Settings::default();
    let mut seen = Vec::new();
    while !payload.is_empty() {
        let (id, value, used) = pair(payload)?;
        payload = &payload[used..];

        if seen.contains(&id) {
            return Err(settings_error(format!("настройка {id:#x} повторена")));
        }
        seen.push(id);
        apply(&mut settings, id, value)?;
    }
    Ok(settings)
}

fn pair(payload: &[u8]) -> H3Result<(u64, u64, usize)> {
    let truncated = || H3Error::protocol(H3_FRAME_ERROR, "SETTINGS обрезан посреди настройки");
    let (id, id_len) = varint::try_decode(payload).ok_or_else(truncated)?;
    let (value, value_len) = varint::try_decode(&payload[id_len..]).ok_or_else(truncated)?;
    Ok((id, value, id_len + value_len))
}

/// Применяет одну настройку. Незнакомые пропускаются (§7.2.4).
fn apply(settings: &mut Settings, id: u64, value: u64) -> H3Result<()> {
    match id {
        MAX_FIELD_SECTION_SIZE => settings.max_field_section_size = Some(value),
        QPACK_MAX_TABLE_CAPACITY => settings.qpack_max_table_capacity = value,
        ENABLE_CONNECT_PROTOCOL => settings.enable_connect_protocol = flag(id, value)?,
        H3_DATAGRAM => settings.h3_datagram = flag(id, value)?,
        // Настройки HTTP/2 без пары в HTTP/3 (§7.2.4.1, §11.2.2).
        0x02..=0x05 => {
            return Err(settings_error(format!("настройка HTTP/2 {id:#x}")));
        }
        _ => {}
    }
    Ok(())
}

/// Булева настройка: только 0 или 1 (RFC 9220, §3; RFC 9297, §2.1.1).
fn flag(id: u64, value: u64) -> H3Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(settings_error(format!(
            "настройка {id:#x} = {value}, а бывает только 0 или 1"
        ))),
    }
}

fn settings_error(reason: String) -> H3Error {
    H3Error::protocol(H3_SETTINGS_ERROR, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_settings_decode_back() {
        let payload = encode(65536, true, (grease_id(3), 7));
        let settings = decode(&payload).expect("разбирается");
        assert_eq!(settings.max_field_section_size, Some(65536));
        assert!(settings.h3_datagram);
        assert!(!settings.enable_connect_protocol);
    }

    #[test]
    fn grease_ids_follow_the_rfc_formula() {
        assert_eq!(grease_id(0), 0x21);
        assert_eq!(grease_id(1), 0x40);
    }

    #[test]
    fn a_server_settings_frame_is_understood() {
        // QPACK_MAX_TABLE_CAPACITY = 0, ENABLE_CONNECT_PROTOCOL = 1,
        // H3_DATAGRAM = 1 и незнакомая 0x21.
        let payload = [0x01, 0x00, 0x08, 0x01, 0x33, 0x01, 0x21, 0x05];
        let settings = decode(&payload).expect("разбирается");
        assert!(settings.enable_connect_protocol);
        assert!(settings.h3_datagram);
    }

    #[test]
    fn http2_settings_and_duplicates_are_refused() {
        for payload in [&[0x02, 0x00][..], &[0x08, 0x01, 0x08, 0x01], &[0x33, 0x02]] {
            let err = decode(payload).expect_err("ошибка SETTINGS");
            assert!(matches!(
                err,
                H3Error::Protocol {
                    code: H3_SETTINGS_ERROR,
                    ..
                }
            ));
        }
    }

    #[test]
    fn a_truncated_pair_is_a_frame_error() {
        let err = decode(&[0x06]).expect_err("обрезано");
        assert!(matches!(
            err,
            H3Error::Protocol {
                code: H3_FRAME_ERROR,
                ..
            }
        ));
    }
}
