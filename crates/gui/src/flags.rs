//! Флаги стран — плитки одного спрайта (`assets/flags.png`).
//!
//! Не эмодзи: на Windows флагов в системном шрифте нет, а подставленный знак
//! другой ширины сдвигает столбцы. Спрайт собран из `flag-icons` 7.6.0 (MIT,
//! набор `4x3`: флаги перерисованы под одну пропорцию, а не вписаны): плитка
//! 32×24, скругление 3 px и тёмная кромка в 14 % — белый флаг не тонет в
//! светлой теме. Между плитками прозрачный зазор: фильтрация не тянет соседа.

use std::sync::LazyLock;

use iced::widget::{Space, image};
use iced::{Element, Length, Rectangle};

use crate::screens::table::GLYPH;

/// Коды в порядке плиток спрайта: слева направо, сверху вниз.
const CODES: [&str; 256] = [
    "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar", "as", "at", "au", "aw", "ax", "az",
    "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bl", "bm", "bn", "bo", "bq", "br", "bs",
    "bt", "bv", "bw", "by", "bz", "ca", "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn",
    "co", "cp", "cr", "cu", "cv", "cw", "cx", "cy", "cz", "de", "dg", "dj", "dk", "dm", "do", "dz",
    "ec", "ee", "eg", "eh", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr", "ga", "gb",
    "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw",
    "gy", "hk", "hm", "hn", "hr", "ht", "hu", "ic", "id", "ie", "il", "im", "in", "io", "iq", "ir",
    "is", "it", "je", "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky",
    "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me",
    "mf", "mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw",
    "mx", "my", "mz", "na", "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om",
    "pa", "pc", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py", "qa",
    "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sj", "sk", "sl",
    "sm", "sn", "so", "sr", "ss", "st", "sv", "sx", "sy", "sz", "tc", "td", "tf", "tg", "th", "tj",
    "tk", "tl", "tm", "tn", "to", "tr", "tt", "tv", "tw", "tz", "ua", "ug", "um", "un", "us", "uy",
    "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws", "xk", "ye", "yt", "za", "zm", "zw",
];

/// Плиток в ряду спрайта.
const COLUMNS: u32 = 16;

/// Размер плитки в пикселях спрайта.
const TILE_WIDTH: u32 = 32;
const TILE_HEIGHT: u32 = 24;

/// Прозрачная кромка между плитками.
const GUTTER: u32 = 2;

/// Высота флага — высота строки: выше — строка таблицы и консоли раздвинется.
const HEIGHT: f32 = GLYPH;

/// Ширина места под флаг; пустое место той же ширины держит столбцы.
pub const WIDTH: f32 = HEIGHT * TILE_WIDTH as f32 / TILE_HEIGHT as f32;

static SPRITE: LazyLock<image::Handle> =
    LazyLock::new(|| image::Handle::from_bytes(&include_bytes!("../../../assets/flags.png")[..]));

/// Флаг страны: место его плитки в спрайте.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flag(u32);

impl Flag {
    /// Флаг по коду ISO 3166-1 (`JP`, `de`); `None` — такого флага нет.
    pub fn of(code: &str) -> Option<Self> {
        let code = code.to_ascii_lowercase();
        let at = CODES.binary_search(&code.as_str()).ok()?;
        u32::try_from(at).ok().map(Self)
    }

    fn region(self) -> Rectangle<u32> {
        Rectangle {
            x: (self.0 % COLUMNS) * (TILE_WIDTH + GUTTER) + GUTTER / 2,
            y: (self.0 / COLUMNS) * (TILE_HEIGHT + GUTTER) + GUTTER / 2,
            width: TILE_WIDTH,
            height: TILE_HEIGHT,
        }
    }
}

/// Флаг либо пустое место той же ширины.
pub fn slot<'a, M: 'a>(flag: Option<Flag>) -> Element<'a, M> {
    match flag {
        Some(flag) => image(SPRITE.clone())
            .crop(flag.region())
            .width(Length::Fixed(WIDTH))
            .height(Length::Fixed(HEIGHT))
            .into(),
        None => Space::new()
            .width(Length::Fixed(WIDTH))
            .height(Length::Fixed(HEIGHT))
            .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Размер `assets/flags.png` из его заголовка IHDR.
    fn sprite_size() -> (u32, u32) {
        let bytes = include_bytes!("../../../assets/flags.png");
        let word = |at: usize| {
            u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        (word(16), word(20))
    }

    #[test]
    fn codes_are_sorted_for_the_search() {
        assert!(CODES.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn every_tile_lies_inside_the_sprite() {
        let (width, height) = sprite_size();
        let rows = CODES.len().div_ceil(COLUMNS as usize) as u32;
        assert_eq!(width, COLUMNS * (TILE_WIDTH + GUTTER));
        assert_eq!(height, rows * (TILE_HEIGHT + GUTTER));

        let last = Flag::of("zw").expect("последний").region();
        assert!(last.x + last.width <= width && last.y + last.height <= height);
    }

    #[test]
    fn a_code_is_found_in_any_case() {
        assert_eq!(Flag::of("JP"), Flag::of("jp"));
        assert_eq!(
            Flag::of("ad").map(Flag::region).map(|r| (r.x, r.y)),
            Some((1, 1))
        );
        assert!(Flag::of("us-east").is_none());
        assert!(Flag::of("").is_none());
    }
}
