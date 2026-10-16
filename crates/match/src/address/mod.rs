//! Сопоставление по адресу назначения: [`ip`], [`domain`], [`port`] и `geo`
//! (за фичей `geo`).

pub mod domain;
#[cfg(feature = "geo")]
pub mod geo;
pub mod ip;
pub mod port;

pub use domain::DomainSet;
#[cfg(feature = "geo")]
pub use geo::{GeoIpDatabase, GeoIpSet};
pub use ip::IpSet;
pub use port::PortSet;
