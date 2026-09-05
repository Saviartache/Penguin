//! Свои порты: кто их занимает и как найти хозяина ответа.
//!
//! У интерфейса внутри тоннеля один адрес на всё. Значит, отличать потоки
//! друг от друга приходится портом — тем самым, что стоит в исходящем пакете
//! отправителем. Это обычный NAT, только очень маленький: за ним всего один
//! клиент, зато адресов назначения у него сколько угодно.
//!
//! ```text
//!   движок ──(приложение, назначение)──► порт ──► пакет наружу
//!   пакет обратно ──► порт ──► (приложение, назначение) ──► движок
//! ```
//!
//! # Почему пул, а не счётчик
//!
//! Порт, занятый закрывшимся соединением, нельзя выдавать сразу: пакеты
//! старого соединения ещё в пути, и новое получит чужой хвост. Пул выдаёт
//! порты по кругу, поэтому между двумя выдачами одного номера проходит весь
//! круг, а не одно закрытие.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Первый номер, который выдаётся.
///
/// Граница из RFC 6335: ниже — порты, назначенные службам, и брать их себе
/// значило бы отвечать на чужой трафик, если он вдруг придёт.
pub const FIRST_PORT: u16 = 49152;

/// Последний номер.
pub const LAST_PORT: u16 = 65535;

/// Сколько сессия UDP живёт без единой датаграммы.
///
/// То же значение, что у входящей стороны (`udp::session`): закрытия у UDP
/// нет, и сессия умирает от тишины.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Пул свободных портов.
#[derive(Debug)]
pub struct PortPool {
    next: u16,
    taken: std::collections::HashSet<u16>,
}

impl PortPool {
    /// Пустой пул.
    pub fn new() -> Self {
        Self {
            next: FIRST_PORT,
            taken: std::collections::HashSet::new(),
        }
    }

    /// Выдаёт свободный порт.
    ///
    /// `None` означает, что заняты все шестнадцать тысяч, — на одном
    /// интерфейсе это не сбой сети, а утечка: кто-то не возвращает порты.
    pub fn take(&mut self) -> Option<u16> {
        let span = usize::from(LAST_PORT - FIRST_PORT) + 1;
        for _ in 0..span {
            let port = self.next;
            self.next = if port == LAST_PORT {
                FIRST_PORT
            } else {
                port + 1
            };
            if self.taken.insert(port) {
                return Some(port);
            }
        }
        None
    }

    /// Возвращает порт в пул.
    pub fn release(&mut self, port: u16) {
        self.taken.remove(&port);
    }

    /// Сколько портов занято.
    pub fn len(&self) -> usize {
        self.taken.len()
    }

    /// Ни одного порта не занято.
    pub fn is_empty(&self) -> bool {
        self.taken.is_empty()
    }
}

impl Default for PortPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Пара, которую надо помнить, чтобы вернуть ответ хозяину.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Flow {
    /// Адрес приложения. На провод не попадает никогда — он нужен только
    /// затем, чтобы движок узнал свою сессию.
    pub app: SocketAddr,
    /// Адрес назначения.
    pub destination: SocketAddr,
}

/// Отображение потоков UDP на свои порты.
#[derive(Debug)]
pub struct UdpNat {
    by_flow: HashMap<Flow, u16>,
    by_port: HashMap<u16, (Flow, Instant)>,
}

impl UdpNat {
    /// Пустое отображение.
    pub fn new() -> Self {
        Self {
            by_flow: HashMap::new(),
            by_port: HashMap::new(),
        }
    }

    /// Порт для потока: найденный или новый.
    pub fn port_for(&mut self, flow: Flow, pool: &mut PortPool, now: Instant) -> Option<u16> {
        if let Some(&port) = self.by_flow.get(&flow) {
            if let Some(entry) = self.by_port.get_mut(&port) {
                entry.1 = now;
            }
            return Some(port);
        }

        let port = pool.take()?;
        self.by_flow.insert(flow, port);
        self.by_port.insert(port, (flow, now));
        Some(port)
    }

    /// Чей это порт.
    ///
    /// Отвечает только если совпал и адрес отправителя: пакет с чужого адреса
    /// на наш порт — это либо чужой ответ, либо подделка, и отдавать его
    /// приложению нельзя.
    pub fn flow_of(&mut self, port: u16, from: SocketAddr, now: Instant) -> Option<Flow> {
        let (flow, last_seen) = self.by_port.get_mut(&port)?;
        if flow.destination != from {
            return None;
        }
        *last_seen = now;
        Some(*flow)
    }

    /// Убирает молчащие потоки и возвращает их порты в пул.
    pub fn expire(&mut self, pool: &mut PortPool, now: Instant) {
        self.by_port.retain(|port, (flow, last_seen)| {
            let alive = now.duration_since(*last_seen) < SESSION_TIMEOUT;
            if !alive {
                pool.release(*port);
                self.by_flow.remove(flow);
            }
            alive
        });
    }

    /// Сколько потоков живо.
    pub fn len(&self) -> usize {
        self.by_port.len()
    }

    /// Ни одного потока.
    pub fn is_empty(&self) -> bool {
        self.by_port.is_empty()
    }
}

impl Default for UdpNat {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(app_port: u16, destination: &str) -> Flow {
        Flow {
            app: format!("10.0.0.2:{app_port}").parse().expect("адрес"),
            destination: destination.parse().expect("адрес"),
        }
    }

    #[test]
    fn ports_start_above_the_well_known_range() {
        // Ниже стоят порты служб; заняв их, мы отвечали бы на чужой трафик.
        let mut pool = PortPool::new();
        assert_eq!(pool.take(), Some(FIRST_PORT));
        const { assert!(FIRST_PORT > 1024) };
    }

    #[test]
    fn a_released_port_is_not_handed_out_again_at_once() {
        // Пакеты закрывшегося соединения ещё в пути, и новое получило бы
        // чужой хвост.
        let mut pool = PortPool::new();
        let first = pool.take().expect("порт");
        let second = pool.take().expect("порт");
        pool.release(first);
        assert_ne!(pool.take(), Some(first));
        assert_ne!(second, first);
    }

    #[test]
    fn the_pool_wraps_around_and_reuses_what_was_returned() {
        let mut pool = PortPool::new();
        let first = pool.take().expect("порт");
        pool.release(first);
        // Проходим весь круг: номер обязан вернуться, иначе пул одноразовый.
        let span = usize::from(LAST_PORT - FIRST_PORT) + 1;
        let mut seen = false;
        for _ in 0..span {
            match pool.take() {
                Some(port) if port == first => {
                    seen = true;
                    break;
                }
                Some(port) => pool.release(port),
                None => break,
            }
        }
        assert!(seen, "возвращённый порт не выдаётся никогда");
    }

    #[test]
    fn an_exhausted_pool_says_so_instead_of_looping() {
        let mut pool = PortPool::new();
        while pool.take().is_some() {}
        assert_eq!(pool.take(), None);
        assert_eq!(pool.len(), usize::from(LAST_PORT - FIRST_PORT) + 1);
    }

    #[test]
    fn the_same_flow_keeps_its_port() {
        // Иначе каждый пакет уходил бы с нового порта, и ответ на предыдущий
        // некому было бы принять.
        let mut pool = PortPool::new();
        let mut nat = UdpNat::new();
        let now = Instant::now();

        let first = nat.port_for(flow(5000, "8.8.8.8:53"), &mut pool, now);
        let again = nat.port_for(flow(5000, "8.8.8.8:53"), &mut pool, now);
        assert_eq!(first, again);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn different_destinations_get_different_ports() {
        let mut pool = PortPool::new();
        let mut nat = UdpNat::new();
        let now = Instant::now();

        let first = nat.port_for(flow(5000, "8.8.8.8:53"), &mut pool, now);
        let second = nat.port_for(flow(5000, "1.1.1.1:53"), &mut pool, now);
        assert_ne!(first, second);
    }

    #[test]
    fn an_answer_from_a_stranger_is_not_delivered() {
        // Пакет на наш порт с чужого адреса — либо чужой ответ, либо
        // подделка; отдать его приложению значит подменить ему собеседника.
        let mut pool = PortPool::new();
        let mut nat = UdpNat::new();
        let now = Instant::now();

        let port = nat
            .port_for(flow(5000, "8.8.8.8:53"), &mut pool, now)
            .expect("порт");
        assert!(
            nat.flow_of(port, "8.8.8.8:53".parse().expect("адрес"), now)
                .is_some()
        );
        assert!(
            nat.flow_of(port, "9.9.9.9:53".parse().expect("адрес"), now)
                .is_none()
        );
    }

    #[test]
    fn an_unknown_port_belongs_to_nobody() {
        let mut nat = UdpNat::new();
        assert!(
            nat.flow_of(50000, "8.8.8.8:53".parse().expect("адрес"), Instant::now())
                .is_none()
        );
    }

    #[test]
    fn a_silent_flow_gives_its_port_back() {
        // Иначе приложение, разославшее пакеты тысяче адресов, оставит после
        // себя тысячу вечно занятых портов.
        let mut pool = PortPool::new();
        let mut nat = UdpNat::new();
        let now = Instant::now();

        nat.port_for(flow(5000, "8.8.8.8:53"), &mut pool, now);
        assert_eq!(pool.len(), 1);

        nat.expire(&mut pool, now + SESSION_TIMEOUT);
        assert!(nat.is_empty());
        assert!(pool.is_empty());
    }

    #[test]
    fn a_busy_flow_is_not_expired() {
        let mut pool = PortPool::new();
        let mut nat = UdpNat::new();
        let start = Instant::now();

        let port = nat
            .port_for(flow(5000, "8.8.8.8:53"), &mut pool, start)
            .expect("порт");

        // Ответ пришёл почти в конце срока — срок обязан начаться заново.
        let later = start + SESSION_TIMEOUT - Duration::from_secs(1);
        nat.flow_of(port, "8.8.8.8:53".parse().expect("адрес"), later);

        nat.expire(&mut pool, start + SESSION_TIMEOUT);
        assert_eq!(nat.len(), 1);
    }
}
