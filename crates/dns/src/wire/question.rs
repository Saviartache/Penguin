//! Секция вопросов: имя, тип, класс.

use super::header::{be16, truncated};
use super::name;
use super::record::RecordType;
use crate::error::DnsResult;

/// Класс IN.
const CLASS_IN: u16 = 1;

/// Читает вопрос: имя и тип; класс не нужен. Возвращает также позицию за вопросом.
pub(super) fn read(msg: &[u8], pos: usize) -> DnsResult<(String, RecordType, usize)> {
    let mut qname = String::with_capacity(32);
    let after_name = name::read(msg, pos, &mut qname)?;
    let record_type = RecordType(be16(msg, after_name)?);
    if msg.len() < after_name + 4 {
        return Err(truncated());
    }
    Ok((qname, record_type, after_name + 4))
}

/// Дописывает вопрос класса IN.
pub(crate) fn write(out: &mut Vec<u8>, qname: &str, record_type: RecordType) -> DnsResult<()> {
    name::write(out, qname)?;
    out.extend_from_slice(&record_type.0.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(())
}
