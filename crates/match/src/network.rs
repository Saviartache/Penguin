//! Сопоставление по виду трафика: TCP/UDP, IPv4/IPv6.

use penguin_core::network::{IpFamily, Network};

use crate::matcher::Matcher;
use crate::target::MatchTarget;

/// Условие по транспортному протоколу.
#[derive(Debug, Clone)]
pub struct NetworkSet(pub Vec<Network>);

/// Условие по версии протокола сети.
#[derive(Debug, Clone)]
pub struct IpFamilySet(pub Vec<IpFamily>);

impl Matcher for NetworkSet {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        self.0.contains(&target.network)
    }

    fn describe(&self) -> String {
        let parts: Vec<&str> = self.0.iter().map(|n| n.as_str()).collect();
        format!("вид трафика в [{}]", parts.join(", "))
    }
}

impl Matcher for IpFamilySet {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        target
            .family()
            .is_some_and(|family| self.0.contains(&family))
    }

    fn describe(&self) -> String {
        let parts: Vec<&str> = self.0.iter().map(|f| f.as_str()).collect();
        format!("версия IP в [{}]", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn target(network: Network, destination: &str) -> MatchTarget<'static> {
        let destination: SocketAddr = destination.parse().expect("адрес");
        MatchTarget::to_address(network, destination)
    }

    #[test]
    fn matches_transport() {
        let set = NetworkSet(vec![Network::Udp]);
        assert!(set.matches(&target(Network::Udp, "1.2.3.4:53")));
        assert!(!set.matches(&target(Network::Tcp, "1.2.3.4:53")));
    }

    #[test]
    fn matches_ip_version() {
        let set = IpFamilySet(vec![IpFamily::V6]);
        assert!(set.matches(&target(Network::Tcp, "[2001:db8::1]:443")));
        assert!(!set.matches(&target(Network::Tcp, "1.2.3.4:443")));
    }

    #[test]
    fn family_follows_the_destination() {
        // Версия берётся из адреса назначения, а не задаётся отдельно:
        // рассогласование этих двух вещей нашло бы себе применение как ошибка.
        assert_eq!(
            target(Network::Tcp, "1.2.3.4:1").family(),
            Some(IpFamily::V4)
        );
        assert_eq!(target(Network::Tcp, "[::1]:1").family(), Some(IpFamily::V6));
    }

    #[test]
    fn family_condition_skips_targets_without_an_address() {
        let target = MatchTarget::to_domain(Network::Tcp, "example.com", 443);
        assert!(!IpFamilySet(vec![IpFamily::V4]).matches(&target));
        assert!(!IpFamilySet(vec![IpFamily::V6]).matches(&target));
    }
}
