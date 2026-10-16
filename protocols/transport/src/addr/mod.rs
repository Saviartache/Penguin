//! Адрес назначения на проводе: [`socks`] (SOCKS5, Trojan, Shadowsocks, Snell, Brook,
//! GOST) и [`v2ray`] (VLESS, VMess: порт перед типом, домен = `2`, не `3`).
//! Домен передаётся доменом, не разрешается.

pub mod socks;
pub mod v2ray;
