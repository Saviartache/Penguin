//! Ресурсные записи ответа.

use std::net::IpAddr;

use super::header::{be16, be32, truncated};
use super::name;
use crate::error::DnsResult;

/// Тип записи (RFC 1035 §3.2.2, RFC 3596); неизвестные хранятся как есть.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordType(pub u16);

impl RecordType {
    /// Адрес IPv4.
    pub const A: Self = Self(1);
    /// Адрес IPv6.
    pub const AAAA: Self = Self(28);
}

/// Указатель на имя вопроса, стоящее сразу за заголовком.
const QUESTION_NAME: [u8; 2] = [0xC0, 0x0C];

/// Запись ответа; данные не копируются.
#[derive(Debug, Clone, Copy)]
pub(super) struct Answer<'a> {
    pub record_type: RecordType,
    pub ttl: u32,
    pub rdata: &'a [u8],
}

impl Answer<'_> {
    /// Адрес из записи `A` или `AAAA`.
    pub(super) fn address(&self) -> Option<IpAddr> {
        match (self.record_type, self.rdata.len()) {
            (RecordType::A, 4) => <[u8; 4]>::try_from(self.rdata).ok().map(IpAddr::from),
            (RecordType::AAAA, 16) => <[u8; 16]>::try_from(self.rdata).ok().map(IpAddr::from),
            _ => None,
        }
    }
}

/// Обход записей секции ответов.
pub(super) struct Answers<'a> {
    msg: &'a [u8],
    pos: usize,
    left: u16,
}

impl<'a> Answers<'a> {
    pub(super) fn new(msg: &'a [u8], pos: usize, count: u16) -> Self {
        Self {
            msg,
            pos,
            left: count,
        }
    }

    fn read(&mut self) -> DnsResult<Answer<'a>> {
        let fixed = name::skip(self.msg, self.pos)?;
        let record_type = RecordType(be16(self.msg, fixed)?);
        let ttl = be32(self.msg, fixed + 4)?;
        let len = usize::from(be16(self.msg, fixed + 8)?);
        let start = fixed + 10;
        let rdata = self.msg.get(start..start + len).ok_or_else(truncated)?;
        self.pos = start + len;
        Ok(Answer {
            record_type,
            ttl,
            rdata,
        })
    }
}

impl<'a> Iterator for Answers<'a> {
    type Item = DnsResult<Answer<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let answer = self.read();
        if answer.is_err() {
            self.left = 0;
        }
        Some(answer)
    }
}

/// Дописывает запись `A` или `AAAA` с именем вопроса.
pub(crate) fn write_address(out: &mut Vec<u8>, address: IpAddr, ttl: u32) {
    match address {
        IpAddr::V4(v4) => write_record(out, RecordType::A, ttl, &v4.octets()),
        IpAddr::V6(v6) => write_record(out, RecordType::AAAA, ttl, &v6.octets()),
    }
}

fn write_record(out: &mut Vec<u8>, record_type: RecordType, ttl: u32, rdata: &[u8]) {
    out.extend_from_slice(&QUESTION_NAME);
    out.extend_from_slice(&record_type.0.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
}
