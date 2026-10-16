//! Чистые сопоставители: без сети, файлов и системных вызовов. Получают
//! [`target::MatchTarget`] и отвечают `true`/`false`; тяжёлое (regex, деревья
//! подсетей, Ахо — Корасик) строится один раз при сборке правил.

pub mod address;
pub mod logic;
pub mod matcher;
pub mod network;
pub mod process;
pub mod target;

pub use address::{DomainSet, IpSet, PortSet};
pub use logic::{All, Always, Any, Not};
pub use matcher::Matcher;
pub use network::{IpFamilySet, NetworkSet};
pub use process::set::{ProcessSet, ProcessSetBuilder};
pub use target::MatchTarget;

#[cfg(test)]
pub(crate) mod test_support {
    use std::net::SocketAddr;

    use penguin_core::network::Network;

    use crate::target::MatchTarget;

    /// Цель по умолчанию: TCP на `1.2.3.4:443`, без имени и без владельца.
    pub(crate) fn target() -> MatchTarget<'static> {
        let destination: SocketAddr = "1.2.3.4:443".parse().expect("адрес");
        MatchTarget::to_address(Network::Tcp, destination)
    }
}
