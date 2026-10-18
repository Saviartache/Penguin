//! Окно списка профилей: какие строки видны и куда их сдвигает колесо.

use std::ops::Range;

/// Сколько профилей видно: ровно столько строк конфигурации список заменяет.
pub const ROWS: usize = 5;

/// Первая видимая строка при открытии: выбранный профиль в окне.
pub fn opened_at(active: Option<usize>, len: usize) -> f32 {
    let top = active.map_or(0, |at| at + 1).saturating_sub(ROWS);
    clamp(top as f32, len)
}

/// Сдвиг колесом, не дальше краёв.
pub fn scrolled(top: f32, rows: f32, len: usize) -> f32 {
    clamp(top + rows, len)
}

/// Номера видимых профилей.
pub fn window(top: f32, len: usize) -> Range<usize> {
    let start = (clamp(top, len) as usize).min(len);
    start..(start + ROWS).min(len)
}

fn clamp(top: f32, len: usize) -> f32 {
    top.clamp(0.0, len.saturating_sub(ROWS) as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_list_never_scrolls() {
        assert_eq!(scrolled(0.0, 3.0, 4), 0.0);
        assert_eq!(window(0.0, 4), 0..4);
    }

    #[test]
    fn the_active_profile_opens_in_view() {
        let top = opened_at(Some(8), 10);
        assert!(window(top, 10).contains(&8));
        assert_eq!(opened_at(Some(1), 10), 0.0);
    }

    #[test]
    fn the_wheel_stops_at_the_last_row() {
        assert_eq!(scrolled(3.0, 10.0, 10), 5.0);
        assert_eq!(scrolled(1.0, -10.0, 10), 0.0);
        assert_eq!(window(5.0, 10), 5..10);
    }

    #[test]
    fn fractions_of_a_row_add_up() {
        let top = scrolled(scrolled(0.0, 0.5, 10), 0.6, 10);
        assert_eq!(window(top, 10), 1..6);
    }
}
