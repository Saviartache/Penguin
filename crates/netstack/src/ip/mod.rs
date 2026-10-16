//! Разбор и контрольные суммы IP-заголовков руками, мимо smoltcp (нужны для TCP до сокета и для UDP).

pub mod checksum;
pub mod parse;

pub use parse::{PROTO_TCP, PROTO_UDP, Packet, parse};
