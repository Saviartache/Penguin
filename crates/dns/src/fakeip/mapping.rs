//! Двустороннее соответствие адрес <-> домен. Именно оно позволяет правилам
//! по доменам работать после подмены.
//!
//! Ради этого fake-IP и существует. Приложение спрашивает у нас адрес
//! `youtube.com`, получает подставной и соединяется с ним; в момент
//! соединения мы по адресу узнаём имя обратно — и правило «youtube.com в
//! тоннель» срабатывает, хотя в самом соединении никакого имени нет.
//!
//! ```text
//!   запрос  youtube.com ──► 198.18.0.7   (прямое отображение)
//!   пакет   на 198.18.0.7 ──► youtube.com (обратное)
//! ```
//!
//! Оба направления обязаны жить одинаково долго: адрес, для которого имя уже
//! забыто, — это соединение, которое уйдёт не туда.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use parking_lot::Mutex;

use super::pool::FakeIpPool;
use crate::error::DnsResult;

/// Сколько соответствий помнить.
///
/// Столько же, сколько имён приложение успевает спросить за время жизни
/// адреса. Восемь тысяч — с запасом; больше означает лишь, что круг адресов
/// замкнётся раньше, чем забудется имя.
pub const MAX_ENTRIES: usize = 8192;

/// Соответствие имён и подставных адресов.
#[derive(Debug)]
pub struct FakeIpMap {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    pool: FakeIpPool,
    to_address: HashMap<Arc<str>, Ipv4Addr>,
    to_domain: HashMap<Ipv4Addr, Arc<str>>,
    /// Порядок выдачи — по нему вытесняются самые старые.
    order: std::collections::VecDeque<Ipv4Addr>,
}

impl FakeIpMap {
    /// Заводит соответствие на указанной подсети.
    pub fn new(cidr: &str) -> DnsResult<Self> {
        Ok(Self {
            inner: Mutex::new(Inner {
                pool: FakeIpPool::parse(cidr)?,
                to_address: HashMap::new(),
                to_domain: HashMap::new(),
                order: std::collections::VecDeque::new(),
            }),
        })
    }

    /// Подставной адрес для имени.
    ///
    /// Повторный запрос того же имени возвращает тот же адрес: приложения
    /// кэшируют ответы, и выдать им второй адрес значило бы держать два
    /// соответствия там, где нужно одно.
    pub fn address_for(&self, domain: &str) -> DnsResult<Ipv4Addr> {
        let mut inner = self.inner.lock();

        if let Some(existing) = inner.to_address.get(domain) {
            return Ok(*existing);
        }

        let address = inner.pool.allocate()?;
        let domain: Arc<str> = Arc::from(domain);

        // Адрес мог быть занят прежним именем — круг замкнулся. Прежнее
        // соответствие снимается целиком, иначе имя осталось бы указывать на
        // чужой адрес.
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

    /// Имя по подставному адресу.
    ///
    /// `None` — адрес не наш или соответствие уже забыто.
    pub fn domain_for(&self, address: Ipv4Addr) -> Option<Arc<str>> {
        self.inner.lock().to_domain.get(&address).cloned()
    }

    /// Наш ли это адрес.
    pub fn is_fake(&self, address: Ipv4Addr) -> bool {
        self.inner.lock().pool.contains(address)
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
        // Главное свойство: имя восстанавливается по адресу — иначе правила
        // по доменам в режиме TUN не работают вовсе.
        let map = map();
        let address = map.address_for("youtube.com").expect("адрес выдан");
        assert_eq!(map.domain_for(address).as_deref(), Some("youtube.com"));
    }

    #[test]
    fn same_domain_gets_the_same_address() {
        // Приложения кэшируют ответы; второй адрес держал бы два соответствия
        // там, где нужно одно.
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
    }

    #[test]
    fn reused_address_forgets_the_old_domain() {
        // Круг замкнулся, адрес достался новому имени. Старое имя не должно
        // продолжать указывать на него: соединение ушло бы не туда.
        let map = FakeIpMap::new("198.18.0.0/30").expect("подсеть разбирается");
        let first = map.address_for("first.example").expect("адрес выдан");

        // Обходим круг, пока адрес не выдастся повторно.
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
        // Старое имя больше не указывает на этот адрес.
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
