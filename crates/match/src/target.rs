//! `MatchTarget` — то, что подаётся на вход сопоставителю: адрес, процесс, сеть.
//!
//! Заимствования, а не владение: цель собирается на каждое новое соединение,
//! и копировать ради этого путь к процессу и доменное имя незачем.
//!
//! # Почему адрес необязателен
//!
//! Соединение приходит к клиенту двумя разными путями, и известно о нём при
//! этом разное:
//!
//! | Путь | Адрес | Имя |
//! |---|---|---|
//! | TUN | известен всегда | появляется позже (fake-IP, SNI) |
//! | SOCKS5 / HTTP | часто неизвестен | приходит от приложения |
//!
//! Приложение, настроенное на прокси, отдаёт **имя** и не разрешает его само
//! — в этом и смысл. Подставить сюда какой-нибудь адрес-заглушку нельзя:
//! правило `dest_ip: ["0.0.0.0/0"]` совпало бы с ним и увело трафик не туда.
//!
//! Поэтому оба поля необязательны и симметричны: условие по адресу не
//! совпадает, когда адреса нет, а условие по имени — когда нет имени.

use std::net::IpAddr;

use penguin_core::network::{IpFamily, Network};

/// Данные соединения в том виде, в каком их читают сопоставители.
#[derive(Debug, Clone, Copy)]
pub struct MatchTarget<'a> {
    /// TCP или UDP.
    pub network: Network,
    /// Адрес назначения, если он известен.
    pub destination_ip: Option<IpAddr>,
    /// Порт назначения. Известен всегда — без него соединение не открыть.
    pub port: u16,
    /// Имя назначения, если известно. Уже нормализовано: нижний регистр,
    /// без завершающей точки.
    pub domain: Option<&'a str>,
    /// Полный путь к процессу-владельцу, нормализованный под платформу.
    pub process_path: Option<&'a str>,
    /// Имя исполняемого файла без пути.
    pub process_name: Option<&'a str>,
}

impl<'a> MatchTarget<'a> {
    /// Цель с известным адресом.
    pub fn to_address(network: Network, destination: std::net::SocketAddr) -> Self {
        Self {
            network,
            destination_ip: Some(destination.ip()),
            port: destination.port(),
            domain: None,
            process_path: None,
            process_name: None,
        }
    }

    /// Цель с известным только именем.
    pub fn to_domain(network: Network, domain: &'a str, port: u16) -> Self {
        Self {
            network,
            destination_ip: None,
            port,
            domain: Some(domain),
            process_path: None,
            process_name: None,
        }
    }

    /// Добавляет имя.
    pub fn with_domain(mut self, domain: &'a str) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Добавляет процесс.
    pub fn with_process(mut self, path: &'a str, name: &'a str) -> Self {
        self.process_path = Some(path);
        self.process_name = Some(name);
        self
    }

    /// Версия протокола сети, если адрес известен.
    pub fn family(&self) -> Option<IpFamily> {
        self.destination_ip.map(IpFamily::of)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_target_knows_the_family() {
        let target = MatchTarget::to_address(Network::Tcp, "1.2.3.4:443".parse().expect("адрес"));
        assert_eq!(target.family(), Some(IpFamily::V4));
        assert_eq!(target.port, 443);
        assert!(target.domain.is_none());
    }

    #[test]
    fn domain_target_has_no_address() {
        // Приложение через прокси отдаёт имя и адреса не знает. Подставлять
        // сюда заглушку нельзя: правило по подсети совпало бы с ней.
        let target = MatchTarget::to_domain(Network::Tcp, "example.com", 443);
        assert!(target.destination_ip.is_none());
        assert!(target.family().is_none());
        assert_eq!(target.domain, Some("example.com"));
    }

    #[test]
    fn builders_compose() {
        let target = MatchTarget::to_address(Network::Tcp, "1.2.3.4:443".parse().expect("адрес"))
            .with_domain("example.com")
            .with_process("c:/apps/app.exe", "app.exe");
        assert_eq!(target.domain, Some("example.com"));
        assert_eq!(target.process_name, Some("app.exe"));
        assert!(target.destination_ip.is_some());
    }
}
