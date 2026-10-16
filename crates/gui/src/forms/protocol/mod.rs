//! Каталог протоколов: описание формы и куда в JSON настроек ложится набранное.
//!
//! Схему параметров знает и проверяет сам протокол, но `protocols/*` подключает
//! только `engine` (AGENTS §1), поэтому окно ловит лишь видимое без сети.
//!
//! Новый протокол: файл рядом со своим [`ProtocolSpec`] и строка в [`catalog::ALL`].

pub mod anytls;
pub mod carrier;
pub mod catalog;
pub mod dpi;
pub mod hysteria2;
pub mod juicity;
pub mod masque;
pub mod masque_ip;
pub mod naive;
pub mod pingwin;
pub mod shadowsocks;
pub mod socks5;
pub mod spec;
#[cfg(test)]
mod testing;
pub mod trojan;
pub mod trusttunnel;
pub mod tuic;
pub mod vless;
pub mod vmess;
pub mod wireguard;

pub use catalog::{ALL, DEFAULT, by_id, by_scheme};
pub use spec::{FieldSpec, ProtocolSpec};
