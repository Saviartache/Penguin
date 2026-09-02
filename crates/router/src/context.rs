//! `FlowContext` — всё, что известно о соединении к моменту решения.
//!
//! Заполняется не сразу и по-разному в зависимости от того, откуда соединение
//! пришло:
//!
//! | Путь | Что известно сразу | Что появляется потом |
//! |---|---|---|
//! | TUN | адрес, процесс | имя — из fake-IP или SNI |
//! | SOCKS5 / HTTP | имя, процесс | адрес — уже на той стороне |
//!
//! Поэтому маршрутизатор вызывается дважды: до и после опознания имени.
//! Второй вызов дешёвый — почти всегда попадает в кэш.
//!
//! Числовой адрес при опознании имени не теряется ([`FlowContext::with_domain`]):
//! правило по подсети должно продолжать работать и после того, как у
//! соединения появилось имя.

use std::net::{IpAddr, SocketAddr};

use penguin_core::address::{Address, SocketAddress};
use penguin_core::network::Network;
use penguin_match::target::MatchTarget;
use penguin_process::identity::ProcessIdentity;

/// Известное о соединении.
#[derive(Debug, Clone)]
pub struct FlowContext {
    /// TCP или UDP.
    pub network: Network,
    /// Откуда соединение пришло внутри машины.
    pub source: SocketAddr,
    /// Куда идёт соединение — так, как его назвало приложение.
    pub destination: SocketAddress,
    /// Числовой адрес, если он известен отдельно от имени.
    pub resolved_ip: Option<IpAddr>,
    /// Процесс-владелец, если его удалось определить.
    ///
    /// `None` — не то же самое, что «системный процесс»: соединение могло
    /// закрыться раньше, чем мы успели заглянуть в таблицу. Правило по
    /// процессу к такому соединению не применяется, и оно уходит по умолчанию
    /// режима, а не блокируется молча.
    pub process: Option<ProcessIdentity>,
}

impl FlowContext {
    /// Соединение к числовому адресу — так приходит трафик из TUN.
    pub fn to_address(network: Network, source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            network,
            source,
            destination: SocketAddress::from(destination),
            resolved_ip: None,
            process: None,
        }
    }

    /// Соединение к имени — так приходит трафик из SOCKS5 и HTTP-прокси.
    pub fn to_target(network: Network, source: SocketAddr, destination: SocketAddress) -> Self {
        Self {
            network,
            source,
            destination,
            resolved_ip: None,
            process: None,
        }
    }

    /// Добавляет опознанное имя, не теряя числовой адрес.
    pub fn with_domain(mut self, domain: Address) -> Self {
        // Адрес сохраняется: иначе правило по подсети переставало бы
        // действовать ровно в тот момент, когда соединение опознали по имени.
        if let Some(ip) = self.destination.host.as_ip() {
            self.resolved_ip = Some(ip);
        }
        self.destination.host = domain;
        self
    }

    /// Добавляет владельца.
    pub fn with_process(mut self, process: ProcessIdentity) -> Self {
        self.process = Some(process);
        self
    }

    /// Числовой адрес назначения, если он известен.
    pub fn destination_ip(&self) -> Option<IpAddr> {
        self.destination.host.as_ip().or(self.resolved_ip)
    }

    /// Имя назначения, если оно известно.
    pub fn domain(&self) -> Option<&str> {
        self.destination.host.as_domain()
    }

    /// Приводит контекст к виду, который читают сопоставители.
    ///
    /// Заимствования, а не копии: цель собирается на каждое соединение, и
    /// копировать ради неё путь к процессу и имя хоста незачем.
    pub fn as_match_target(&self) -> MatchTarget<'_> {
        MatchTarget {
            network: self.network,
            destination_ip: self.destination_ip(),
            port: self.destination.port,
            domain: self.domain(),
            process_path: self.process.as_ref().map(|p| &*p.path),
            process_name: self.process.as_ref().map(|p| &*p.name),
        }
    }
}

#[cfg(test)]
mod tests {
    use penguin_core::network::IpFamily;

    use super::*;

    fn source() -> SocketAddr {
        "127.0.0.1:50000".parse().expect("адрес")
    }

    fn from_tun() -> FlowContext {
        FlowContext::to_address(
            Network::Tcp,
            source(),
            "1.2.3.4:443".parse().expect("адрес"),
        )
    }

    #[test]
    fn tun_flow_knows_the_address_but_not_the_name() {
        let context = from_tun();
        let target = context.as_match_target();
        assert_eq!(
            target.destination_ip,
            Some("1.2.3.4".parse().expect("адрес"))
        );
        assert_eq!(target.port, 443);
        assert!(target.domain.is_none());
        assert_eq!(target.family(), Some(IpFamily::V4));
    }

    #[test]
    fn proxy_flow_knows_the_name_but_not_the_address() {
        // Приложение через прокси отдало имя и разрешать его не стало —
        // адреса здесь взяться неоткуда.
        let context = FlowContext::to_target(
            Network::Tcp,
            source(),
            SocketAddress::domain("example.com", 443),
        );
        let target = context.as_match_target();
        assert_eq!(target.domain, Some("example.com"));
        assert!(target.destination_ip.is_none());
        assert_eq!(target.port, 443);
    }

    #[test]
    fn sniffed_name_does_not_erase_the_address() {
        // Главное свойство: после опознания имени правила по подсети обязаны
        // продолжать работать.
        let context = from_tun().with_domain(Address::domain("Example.COM"));
        let target = context.as_match_target();
        assert_eq!(target.domain, Some("example.com"));
        assert_eq!(
            target.destination_ip,
            Some("1.2.3.4".parse().expect("адрес"))
        );
    }

    #[test]
    fn process_reaches_the_matcher_normalized() {
        let context = from_tun().with_process(ProcessIdentity::new(1, "/apps/app"));
        let target = context.as_match_target();
        assert_eq!(target.process_path, Some("/apps/app"));
        assert_eq!(target.process_name, Some("app"));
    }

    #[test]
    fn family_follows_the_destination() {
        let context = FlowContext::to_address(
            Network::Udp,
            "[::1]:50000".parse().expect("адрес"),
            "[2001:db8::1]:53".parse().expect("адрес"),
        );
        assert_eq!(context.as_match_target().family(), Some(IpFamily::V6));
    }
}
