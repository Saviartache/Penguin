//! Выдача и возврат адресов из пула.
//!
//! Адреса раздаются подряд по кругу. Возврата в пул нет и не нужно: круг
//! длиной в сто тридцать тысяч адресов (`198.18.0.0/15`) при тысяче запросов
//! в минуту замыкается за двое суток, а сопоставление адреса и имени живёт
//! минуты.
//!
//! Служебные адреса пропускаются: нулевой адрес подсети и широковещательный
//! приложениям выдавать нельзя — часть из них проверяет адрес на осмысленность
//! и отказывается соединяться.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::error::{DnsError, DnsResult};

/// Круговой распределитель подставных адресов.
#[derive(Debug)]
pub struct FakeIpPool {
    network: Ipv4Net,
    /// Смещение следующего адреса от начала подсети.
    next: u32,
    /// Сколько адресов пригодно к выдаче.
    usable: u32,
}

impl FakeIpPool {
    /// Заводит пул на указанной подсети.
    pub fn new(network: Ipv4Net) -> DnsResult<Self> {
        let total = network.hosts().count() as u32;
        if total < 2 {
            return Err(DnsError::Config(format!(
                "подсеть `{network}` слишком мала для подставных адресов"
            )));
        }

        Ok(Self {
            network,
            next: 1,
            usable: total,
        })
    }

    /// Разбирает подсеть из настроек.
    pub fn parse(cidr: &str) -> DnsResult<Self> {
        let network: Ipv4Net = cidr
            .parse()
            .map_err(|_| DnsError::Config(format!("не разбирается подсеть `{cidr}`")))?;
        Self::new(network)
    }

    /// Следующий адрес.
    pub fn allocate(&mut self) -> DnsResult<Ipv4Addr> {
        if self.usable == 0 {
            return Err(DnsError::FakeIpExhausted);
        }

        let base = u32::from(self.network.network());
        let broadcast = u32::from(self.network.broadcast());

        // Круг: дойдя до конца подсети, начинаем сначала. Первый адрес
        // подсети пропускается — он служебный.
        let mut candidate = base.wrapping_add(self.next);
        if candidate >= broadcast {
            self.next = 1;
            candidate = base + 1;
        }
        self.next += 1;

        Ok(Ipv4Addr::from(candidate))
    }

    /// Принадлежит ли адрес пулу.
    ///
    /// По этому вопросу движок отличает подставной адрес от настоящего: для
    /// первого имя известно, второй идёт как есть.
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        self.network.contains(&address)
    }

    /// Подсеть пула.
    pub fn network(&self) -> Ipv4Net {
        self.network
    }

    /// Сколько адресов в круге.
    pub fn capacity(&self) -> u32 {
        self.usable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(cidr: &str) -> FakeIpPool {
        FakeIpPool::parse(cidr).expect("подсеть разбирается")
    }

    #[test]
    fn allocates_inside_the_network() {
        let mut pool = pool("198.18.0.0/15");
        for _ in 0..1000 {
            let address = pool.allocate().expect("адрес выдан");
            assert!(pool.contains(address), "{address} вне подсети");
        }
    }

    #[test]
    fn skips_the_network_address() {
        // Нулевой адрес подсети приложениям выдавать нельзя: часть из них
        // проверяет адрес и отказывается соединяться.
        let mut pool = pool("198.18.0.0/15");
        for _ in 0..100 {
            assert_ne!(
                pool.allocate().expect("адрес выдан"),
                Ipv4Addr::new(198, 18, 0, 0)
            );
        }
    }

    #[test]
    fn addresses_do_not_repeat_within_a_lap() {
        let mut pool = pool("198.18.0.0/24");
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            assert!(
                seen.insert(pool.allocate().expect("адрес выдан")),
                "адрес повторился"
            );
        }
    }

    #[test]
    fn wraps_around_instead_of_failing() {
        // Круг обязан замкнуться: остановиться на исчерпании пула значило бы
        // перестать разрешать имена насовсем.
        let mut pool = pool("198.18.0.0/24");
        for _ in 0..1000 {
            let address = pool.allocate().expect("адрес выдан");
            assert!(pool.contains(address));
        }
    }

    #[test]
    fn does_not_hand_out_the_broadcast_address() {
        let mut pool = pool("198.18.0.0/24");
        let broadcast = Ipv4Addr::new(198, 18, 0, 255);
        for _ in 0..1000 {
            assert_ne!(pool.allocate().expect("адрес выдан"), broadcast);
        }
    }

    #[test]
    fn rejects_a_subnet_that_is_too_small() {
        assert!(FakeIpPool::parse("198.18.0.1/32").is_err());
        assert!(FakeIpPool::parse("не подсеть").is_err());
    }

    #[test]
    fn foreign_addresses_are_not_ours() {
        let pool = pool("198.18.0.0/15");
        assert!(!pool.contains(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(pool.contains(Ipv4Addr::new(198, 18, 5, 7)));
    }
}
