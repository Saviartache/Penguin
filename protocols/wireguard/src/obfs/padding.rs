//! Хвосты AmneziaWG 3: случайный хвост (`random_trailers`) и добавка к
//! содержимому (`content_padding_addition`). Обе ограничены «окном UDP» —
//! наибольшей виденной датаграммой, чтобы не выдать себя необычной длиной
//! (`udpWindow`, `randomTrailer`, `randomPaddingAddition` в `device/send.go`).

use penguin_proto::random;

use crate::obfs::engine::UintRange;

/// Начальное окно (`DefaultUdpWindow`).
const DEFAULT_UDP_WINDOW: usize = 500;

/// Наибольшая виденная длина датаграммы (`peer.udpWindow`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UdpWindow(usize);

impl Default for UdpWindow {
    fn default() -> Self {
        Self(DEFAULT_UDP_WINDOW)
    }
}

impl UdpWindow {
    /// Учитывает датаграмму длиной `len`.
    pub(super) fn observe(&mut self, len: usize) {
        self.0 = self.0.max(len);
    }

    /// Случайный хвост `[0, окно − size)`; пакет не меньше окна — без хвоста.
    pub(super) fn trailer(self, size: usize) -> usize {
        match self.0.checked_sub(size) {
            Some(space) if space > 0 => random::range(0..space as u64) as usize,
            _ => 0,
        }
    }

    /// Добавка из диапазона, урезанная до свободного места в окне.
    pub(super) fn addition(self, range: UintRange, size: usize) -> usize {
        let space = self.0.saturating_sub(size);
        (range.pick_value() as usize).min(space)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_starts_at_the_reference_default_and_only_grows() {
        let mut window = UdpWindow::default();
        assert_eq!(window, UdpWindow(500));
        window.observe(300);
        assert_eq!(window, UdpWindow(500));
        window.observe(1200);
        assert_eq!(window, UdpWindow(1200));
    }

    #[test]
    fn a_trailer_never_pushes_the_packet_past_the_window() {
        let window = UdpWindow(500);
        for _ in 0..200 {
            assert!(window.trailer(200) < 300);
        }
        assert_eq!(window.trailer(500), 0);
        assert_eq!(window.trailer(900), 0);
    }

    #[test]
    fn an_addition_is_taken_from_the_range_and_clipped_to_the_window() {
        let window = UdpWindow(500);
        for _ in 0..200 {
            let add = window.addition(UintRange::new(10, 20), 100);
            assert!((10..=20).contains(&add), "{add}");
        }
        assert_eq!(window.addition(UintRange::new(100, 100), 450), 50);
        assert_eq!(window.addition(UintRange::new(100, 100), 600), 0);
    }
}
