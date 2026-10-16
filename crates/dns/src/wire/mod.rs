//! Двоичный формат DNS-сообщений (RFC 1035): заголовок, имена, вопросы, записи.

mod header;
mod name;
mod packet;
mod question;
mod record;

pub(crate) use header::{HEADER_LEN, NXDOMAIN, QR, RA, RD, write_header};
pub(crate) use packet::Packet;
pub(crate) use question::write as write_question;
pub use record::RecordType;
pub(crate) use record::write_address;
