//! Разбор сообщения целиком.

use std::net::IpAddr;

use super::header::{HEADER_LEN, Header, truncated};
use super::name;
use super::question;
use super::record::{Answers, RecordType};
use crate::error::DnsResult;

/// Разобранные заголовок и граница секции ответов.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Packet<'a> {
    msg: &'a [u8],
    header: Header,
    answers_at: usize,
}

impl<'a> Packet<'a> {
    /// Проверяет заголовок и секцию вопросов.
    pub(crate) fn parse(msg: &'a [u8]) -> DnsResult<Self> {
        let header = Header::parse(msg)?;
        let mut pos = HEADER_LEN;
        for _ in 0..header.questions {
            pos = name::skip(msg, pos)? + 4;
            if pos > msg.len() {
                return Err(truncated());
            }
        }
        Ok(Self {
            msg,
            header,
            answers_at: pos,
        })
    }

    /// Идентификатор запроса.
    pub(crate) fn id(&self) -> u16 {
        self.header.id
    }

    /// Код ответа.
    pub(crate) fn rcode(&self) -> u16 {
        self.header.rcode()
    }

    /// Первый вопрос: имя в нижнем регистре и тип.
    pub(crate) fn question(&self) -> DnsResult<Option<(String, RecordType)>> {
        if self.header.questions == 0 {
            return Ok(None);
        }
        let (name, record_type, _) = question::read(self.msg, HEADER_LEN)?;
        Ok(Some((name, record_type)))
    }

    /// Адреса из записей `A` и `AAAA`; остальные типы пропускаются.
    pub(crate) fn addresses(&self) -> DnsResult<Vec<IpAddr>> {
        let mut found = Vec::new();
        for answer in self.answers() {
            found.extend(answer?.address());
        }
        Ok(found)
    }

    /// Наименьший TTL среди ответов.
    pub(crate) fn min_ttl(&self) -> DnsResult<Option<u32>> {
        let mut min = None;
        for answer in self.answers() {
            let ttl = answer?.ttl;
            min = Some(min.map_or(ttl, |m: u32| m.min(ttl)));
        }
        Ok(min)
    }

    fn answers(&self) -> Answers<'a> {
        Answers::new(self.msg, self.answers_at, self.header.answers)
    }
}
