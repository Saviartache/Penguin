//! Порты и диапазоны портов.

use crate::matcher::Matcher;
use crate::target::MatchTarget;

/// Набор портов и диапазонов.
///
/// Отдельные порты в отсортированном списке, диапазоны — рядом. Портов в
/// правиле редко бывает больше десятка, и заводить под них хеш-таблицу или
/// битовую карту на 65 536 значений незачем: двоичный поиск по короткому
/// массиву быстрее обоих за счёт кэша.
#[derive(Debug, Default)]
pub struct PortSet {
    singles: Vec<u16>,
    ranges: Vec<(u16, u16)>,
}

impl PortSet {
    /// Пустой набор.
    pub fn new() -> Self {
        Self::default()
    }

    /// Набор из отдельных портов.
    pub fn from_ports<I: IntoIterator<Item = u16>>(ports: I) -> Self {
        let mut singles: Vec<u16> = ports.into_iter().collect();
        singles.sort_unstable();
        singles.dedup();
        Self {
            singles,
            ranges: Vec::new(),
        }
    }

    /// Набор из диапазонов, включительно с обеих сторон.
    pub fn from_ranges<I: IntoIterator<Item = (u16, u16)>>(ranges: I) -> Self {
        let ranges = ranges
            .into_iter()
            // Границы приводятся в порядок: `443-80` пользователь пишет по
            // невнимательности, и это не повод отказывать.
            .map(|(a, b)| if a <= b { (a, b) } else { (b, a) })
            .collect();
        Self {
            singles: Vec::new(),
            ranges,
        }
    }

    /// Добавляет отдельные порты.
    pub fn add_ports<I: IntoIterator<Item = u16>>(&mut self, ports: I) {
        self.singles.extend(ports);
        self.singles.sort_unstable();
        self.singles.dedup();
    }

    /// Добавляет диапазоны.
    pub fn add_ranges<I: IntoIterator<Item = (u16, u16)>>(&mut self, ranges: I) {
        self.ranges.extend(
            ranges
                .into_iter()
                .map(|(a, b)| if a <= b { (a, b) } else { (b, a) }),
        );
    }

    /// Входит ли порт в набор.
    pub fn contains(&self, port: u16) -> bool {
        self.singles.binary_search(&port).is_ok()
            || self
                .ranges
                .iter()
                .any(|(from, to)| (*from..=*to).contains(&port))
    }

    /// Набор пуст.
    pub fn is_empty(&self) -> bool {
        self.singles.is_empty() && self.ranges.is_empty()
    }
}

impl Matcher for PortSet {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        self.contains(target.port)
    }

    fn describe(&self) -> String {
        let mut parts: Vec<String> = self.singles.iter().map(u16::to_string).collect();
        parts.extend(self.ranges.iter().map(|(from, to)| format!("{from}-{to}")));
        format!("порт в [{}]", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_single_ports() {
        let set = PortSet::from_ports([80, 443]);
        assert!(set.contains(80));
        assert!(set.contains(443));
        assert!(!set.contains(8080));
    }

    #[test]
    fn matches_ranges_inclusively() {
        let set = PortSet::from_ranges([(8000, 8100)]);
        assert!(set.contains(8000));
        assert!(set.contains(8050));
        assert!(set.contains(8100));
        assert!(!set.contains(7999));
        assert!(!set.contains(8101));
    }

    #[test]
    fn reversed_range_is_accepted() {
        // Пользователь пишет `443-80` по невнимательности; отказывать из-за
        // этого не за что.
        let set = PortSet::from_ranges([(443, 80)]);
        assert!(set.contains(100));
        assert!(!set.contains(500));
    }

    #[test]
    fn combines_ports_and_ranges() {
        let mut set = PortSet::from_ports([53]);
        set.add_ranges([(8000, 8100)]);
        assert!(set.contains(53));
        assert!(set.contains(8080));
        assert!(!set.contains(80));
    }

    #[test]
    fn boundary_ports_work() {
        let set = PortSet::from_ports([0, 65535]);
        assert!(set.contains(0));
        assert!(set.contains(65535));
    }

    #[test]
    fn empty_set_matches_nothing() {
        let set = PortSet::new();
        assert!(set.is_empty());
        assert!(!set.contains(443));
    }

    #[test]
    fn duplicates_are_collapsed() {
        let set = PortSet::from_ports([443, 443, 443]);
        assert_eq!(set.singles, vec![443]);
    }
}
