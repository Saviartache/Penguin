//! Заголовок сообщения: 12 байт.

use crate::error::{DnsError, DnsResult};

/// Длина заголовка.
pub(crate) const HEADER_LEN: usize = 12;

/// Флаг ответа.
pub(crate) const QR: u16 = 0x8000;
/// Рекурсия желательна.
pub(crate) const RD: u16 = 0x0100;
/// Рекурсия доступна.
pub(crate) const RA: u16 = 0x0080;
/// Код ответа «имени нет».
pub(crate) const NXDOMAIN: u16 = 3;

/// Разобранный заголовок.
#[derive(Debug, Clone, Copy)]
pub(super) struct Header {
    pub id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answers: u16,
}

impl Header {
    pub(super) fn parse(msg: &[u8]) -> DnsResult<Self> {
        if msg.len() < HEADER_LEN {
            return Err(truncated());
        }
        Ok(Self {
            id: be16(msg, 0)?,
            flags: be16(msg, 2)?,
            questions: be16(msg, 4)?,
            answers: be16(msg, 6)?,
        })
    }

    pub(super) fn rcode(self) -> u16 {
        self.flags & 0x000F
    }
}

/// Дописывает заголовок без записей authority и additional.
pub(crate) fn write_header(out: &mut Vec<u8>, id: u16, flags: u16, answers: u16) {
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&[0; 4]);
}

pub(super) fn truncated() -> DnsError {
    DnsError::Malformed("сообщение обрезано".to_owned())
}

pub(super) fn be16(msg: &[u8], pos: usize) -> DnsResult<u16> {
    let bytes = msg.get(pos..pos + 2).ok_or_else(truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub(super) fn be32(msg: &[u8], pos: usize) -> DnsResult<u32> {
    let bytes = msg.get(pos..pos + 4).ok_or_else(truncated)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips() {
        let mut out = Vec::new();
        write_header(&mut out, 0xABCD, QR | RD | NXDOMAIN, 2);
        assert_eq!(out.len(), HEADER_LEN);

        let header = Header::parse(&out).expect("разбирается");
        assert_eq!(
            (header.id, header.questions, header.answers),
            (0xABCD, 1, 2)
        );
        assert_eq!(header.rcode(), NXDOMAIN);
        assert_eq!(header.flags & QR, QR);
    }

    #[test]
    fn short_header_is_rejected() {
        assert!(Header::parse(&[0; HEADER_LEN - 1]).is_err());
    }
}
