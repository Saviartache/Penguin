//! Двустороннее соответствие адрес <-> домен: оно возвращает правилам по
//! доменам имя, которого в соединении нет.
//!
//! Оба направления живут одинаково долго: адрес без имени — соединение не туда.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;

use ipnet::Ipv4Net;
use parking_lot::Mutex;

use super::pool::FakeIpPool;
use crate::error::DnsResult;

/// Сколько соответствий помнить.
pub const MAX_ENTRIES: usize = 8192;

/// Соответствие имён и подставных адресов.
#[derive(Debug)]
pub struct FakeIpMap {
    /// Вне замка: `is_fake` спрашивают на каждом соединении.
    network: Ipv4Net,
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    pool: FakeIpPool,
    to_address: HashMap<Arc<str>, Ipv4Addr>,
    to_domain: HashMap<Ipv4Addr, Arc<str>>,
    /// Порядок выдачи: по нему вытесняются самые старые.
    order: VecDeque<Ipv4Addr>,
}

impl FakeIpMap {
    /// Заводит соответствие на указанной подсети.
    pub fn new(cidr: &str) -> DnsResult<Self> {
        let pool = FakeIpPool::parse(cidr)?;
        Ok(Self {
            network: pool.network(),
            inner: Mutex::new(Inner {
                pool,
                to_address: HashMap::new(),
                to_domain: HashMap::new(),
                order: VecDeque::new(),
            }),
        })
    }

    /// Подставной адрес для имени; то же имя получает тот же адрес.
    pub fn address_for(&self, domain: &str) -> DnsResult<Ipv4Addr> {
        let mut inner = self.inner.lock();

        if let Some(existing) = inner.to_address.get(domain) {
            return Ok(*existing);
        }

        let address = inner.pool.allocate()?;
        let domain: Arc<str> = Arc::from(domain);

        // Круг замкнулся: прежнее имя адреса снимается целиком.
        if let Some(previous) = inner.to_domain.insert(address, Arc::clone(&domain)) {
            inner.to_address.remove(&previous);
        }
        inner.to_address.insert(domain, address);
        inner.order.push_back(address);

        while inner.order.len() > MAX_ENTRIES {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            if let Some(domain) = inner.to_domain.remove(&oldest) {
                inner.to_address.remove(&domain);
            }
        }

        Ok(address)
    }

    /// Имя по подставному адресу; `None` — адрес не наш или имя забыто.
    pub fn domain_for(&self, address: Ipv4Addr) -> Option<Arc<str>> {
        self.inner.lock().to_domain.get(&address).cloned()
    }

    /// Наш ли это адрес.
    pub fn is_fake(&self, address: Ipv4Addr) -> bool {
        self.network.contains(&address)
    }

    /// Сколько соответствий помнится.
    pub fn len(&self) -> usize {
        self.inner.lock().to_domain.len()
    }

    /// Соответствий нет.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Забывает всё — при переподключении.
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.to_address.clear();
        inner.to_domain.clear();
        inner.order.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> FakeIpMap {
        FakeIpMap::new("198.18.0.0/15").expect("подсеть разбирается")
    }

    #[test]
    fn round_trips_domain_and_address() {
        let map = map();
        let address = map.address_for("youtube.com").expect("адрес выдан");
        assert_eq!(map.domain_for(address).as_deref(), Some("youtube.com"));
    }

    #[test]
    fn same_domain_gets_the_same_address() {
        let map = map();
        let first = map.address_for("example.com").expect("адрес выдан");
        let second = map.address_for("example.com").expect("адрес выдан");
        assert_eq!(first, second);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn different_domains_get_different_addresses() {
        let map = map();
        let first = map.address_for("a.example").expect("адрес выдан");
        let second = map.address_for("b.example").expect("адрес выдан");
        assert_ne!(first, second);
    }

    #[test]
    fn foreign_addresses_have_no_domain() {
        let map = map();
        assert!(map.domain_for(Ipv4Addr::new(8, 8, 8, 8)).is_none());
        assert!(!map.is_fake(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(map.is_fake(Ipv4Addr::new(198, 18, 0, 7)));
    }

    #[test]
    fn reused_address_forgets_the_old_domain() {
        let map = FakeIpMap::new("198.18.0.0/30").expect("подсеть разбирается");
        let first = map.address_for("first.example").expect("адрес выдан");

        let mut reused = false;
        for step in 0..50 {
            let domain = format!("host{step}.example");
            if map.address_for(&domain).expect("адрес выдан") == first {
                reused = true;
                assert_eq!(map.domain_for(first).as_deref(), Some(domain.as_str()));
                break;
            }
        }
        assert!(reused, "адрес так и не переиспользовался");
        assert_ne!(
            map.address_for("first.example").expect("адрес выдан"),
            first
        );
    }

    #[test]
    fn map_is_bounded() {
        let map = map();
        for step in 0..(MAX_ENTRIES + 500) {
            map.address_for(&format!("host{step}.example"))
                .expect("адрес выдан");
        }
        assert!(
            map.len() <= MAX_ENTRIES,
            "соответствий накопилось {}",
            map.len()
        );
    }

    #[test]
    fn clear_forgets_everything() {
        let map = map();
        map.address_for("example.com").expect("адрес выдан");
        map.clear();
        assert!(map.is_empty());
    }
}
