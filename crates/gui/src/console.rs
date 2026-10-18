//! Консольное окно главного экрана в духе `MEM`/`CHKDSK`.
//!
//! Рамки нет: строка — ряд виджетов, пустоту между полем и значением растягивает
//! контейнер, поэтому ширину в знаках никто не считает.
//!
//! Только знаки, которые есть в шрифте кита (ASCII, кириллица, `─`, `▁`..`█`):
//! значение встаёт по правому краю измеренной шириной, а подставленный из
//! системного шрифта знак шире и вылезает за край. Потому прочерк — дефис, а
//! обрезанный хвост — [`CUT`].

mod choice;

use std::sync::LazyLock;

use iced::mouse::Interaction;
use iced::theme::Palette;
use iced::time::Duration;
use iced::widget::text::{IntoFragment, LineHeight, Wrapping};
use iced::widget::{container, mouse_area, text};
use iced::{Color, Element, Length, Padding};
use uikit::layout::{Flex, Sizable, Size, px};
use uikit::tokens::{ink, type_scale};
use uikit::widgets::BitStream;

/// Кегль консоли.
const SIZE: f32 = type_scale::BODY;

/// Высота строки текста — ровно кегль; запас стоит снаружи, в [`SPACING`].
const LINE: f32 = SIZE;

/// Зазор между любыми двумя строками, включая поток: треть кегля.
const SPACING: f32 = SIZE / 3.0;

/// Ширина знака ZedMono относительно кегля; нужна для отступов, не для раскладки.
const ADVANCE: f32 = 0.55;

/// Ширина знака в точках.
const CELL: f32 = SIZE * ADVANCE;

/// Отступ от края со всех сторон; значение у самого края читается как вылезшее.
const PAD: f32 = CELL * 2.0;

/// Курсор.
const CURSOR: char = '█';

/// Точки между полем и значением.
const LEADER: char = '.';

/// Черта в заголовке раздела.
const DASH: char = '─';

/// Длина заполнителя в знаках: с запасом больше любого окна, режется контейнером.
const FILLER: usize = 240;

/// За сколько поток набирается по ячейкам.
const STREAM_REVEAL: Duration = Duration::from_secs(2);

/// Насколько зазор под потоком шире зазора над ним (подобрано на экране).
const STREAM_SKEW: f32 = SIZE / 6.0;

/// Предел длины значения в знаках: защита от длинного имени профиля.
const LIMIT: usize = 48;

/// Знак на месте обрезанного хвоста: тильда есть в моноширинном шрифте кита.
const CUT: char = '~';

static DOTS: LazyLock<String> = LazyLock::new(|| filler_of(LEADER));
static RULE: LazyLock<String> = LazyLock::new(|| filler_of(DASH));

fn filler_of(glyph: char) -> String {
    std::iter::repeat_n(glyph, FILLER).collect()
}

/// Одна строка консоли.
pub enum Line {
    /// Заголовок раздела: имя и черта до правого края.
    Section(String),
    /// Поле и значение, точки между ними до правого края.
    Pair(String, String),
    /// То же, но значение своим цветом — состояние тоннеля.
    Toned(String, String, Color),
    /// Как [`Line::Pair`], но нажатие на значение шлёт [`Picker::toggle`].
    Pick(String, String),
    /// Пункт списка под [`Line::Pick`]: имя, примечание, выбран ли, номер для [`Picker::choose`].
    Choice(String, String, bool, usize),
    /// Пустая строка той же высоты: держит место короткого списка.
    Blank,
    /// Поток данных: загрузка от нуля до единицы; не больше одного на экран.
    Stream(f32),
    /// Пустота на всю свободную высоту: держит место потока и прижимает нижние строки.
    Space,
}

/// Сколько консоли показывать.
#[derive(Debug, Clone, Copy)]
pub enum Reveal {
    /// Напечатано всё.
    Done,
    /// Печатается: доля напечатанного, `0.0..=1.0`.
    Typing(f32),
}

/// Что шлют строки выбора.
pub struct Picker<Message> {
    /// Нажатие на значение [`Line::Pick`].
    pub toggle: Message,
    /// Нажатие на [`Line::Choice`] с этим номером.
    pub choose: fn(usize) -> Message,
    /// Колесо над списком, в строках: вниз — плюс.
    pub scroll: fn(f32) -> Message,
}

/// Собирает консоль во всё окно; без `picker` строки выбора не нажимаются.
pub fn console<'a, Message: Clone + 'a>(
    palette: &Palette,
    lines: &[Line],
    reveal: Reveal,
    picker: Option<&Picker<Message>>,
) -> Element<'a, Message> {
    let total: usize = lines.iter().map(cost).sum();
    let typed = match reveal {
        Reveal::Done => total,
        Reveal::Typing(fraction) => ((total as f32) * fraction.clamp(0.0, 1.0)).ceil() as usize,
    };

    let mut body = Flex::col().w(Size::FILL).h(Size::FILL).gap(SPACING);
    let mut at = 0;
    for line in lines {
        let end = at + cost(line);
        // Ненабранная строка отсутствует: появляется сверху вниз.
        let shown = if typed >= end {
            Some(draw(palette, line, None, picker))
        } else if typed > at {
            Some(draw(palette, line, Some(typed - at), None))
        } else {
            None
        };
        at = end;

        if let Some(element) = shown {
            body = match line {
                Line::Stream(_) | Line::Space => body.push(element),
                // Высота явная: точки и черта мерятся разными шрифтами.
                _ => body.push_sized(element, px(LINE)),
            };
        }
    }

    container(body.build())
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(Padding::new(PAD))
        .style(uikit::container::log_terminal_viewport as fn(&iced::Theme) -> _)
        .clip(true)
        .into()
}

/// Сколько знаков «набирается» в строке; поток появляется целиком.
fn cost(line: &Line) -> usize {
    match line {
        Line::Pair(label, value) | Line::Toned(label, value, _) | Line::Pick(label, value) => {
            count(label) + count(value)
        }
        Line::Section(label) => count(label),
        // Список открывают уже напечатанной консоли.
        Line::Choice(..) | Line::Blank | Line::Stream(_) | Line::Space => 0,
    }
}

/// Рисует строку; `typed` — сколько знаков набрано, `None` — вся.
fn draw<'a, Message: Clone + 'a>(
    palette: &Palette,
    line: &Line,
    typed: Option<usize>,
    picker: Option<&Picker<Message>>,
) -> Element<'a, Message> {
    match line {
        Line::Section(label) => section(palette, label, typed),
        Line::Pair(label, value) => duo(palette, label, value, palette.text, typed, None),
        Line::Toned(label, value, tone) => duo(palette, label, value, *tone, typed, None),
        Line::Pick(label, value) => {
            let toggle = picker.map(|picker| picker.toggle.clone());
            duo(palette, label, value, palette.text, typed, toggle)
        }
        Line::Choice(name, note, chosen, index) => {
            choice::row(palette, name, note, *chosen, *index, picker)
        }
        Line::Blank => iced::widget::Space::new().width(Length::Fill).into(),
        Line::Stream(load) => stream(*load),
        Line::Space => iced::widget::Space::new()
            .width(Length::Fill)
            .height(Length::Fill)
            .into(),
    }
}

fn section<'a, Message: 'a>(
    palette: &Palette,
    label: &str,
    typed: Option<usize>,
) -> Element<'a, Message> {
    let (shown, ruled) = match typed {
        None => (label.to_owned(), true),
        // Черта дорисовывается, когда имя набрано.
        Some(shown) => (typing(label, shown, count(label)), false),
    };

    Flex::row()
        .w(Size::FILL)
        .push_auto(cell(shown, palette.text))
        .push(filler(palette, &RULE, ruled))
        .gap(CELL)
        .build()
}

/// Поле слева, значение у правого края; с `on_press` значение нажимается.
fn duo<'a, Message: Clone + 'a>(
    palette: &Palette,
    label: &str,
    value: &str,
    value_ink: Color,
    typed: Option<usize>,
    on_press: Option<Message>,
) -> Element<'a, Message> {
    let label_ink = ink::level(palette, ink::SECONDARY);
    let value = clip(value, LIMIT);
    let (label_len, value_len) = (count(label), count(&value));
    let (label_shown, dotted, value_shown) = match typed {
        None => (label.to_owned(), true, value),
        // Место под значение занято пробелами, чтобы точки не ехали.
        Some(shown) if shown < label_len => (
            typing(label, shown, label_len),
            false,
            " ".repeat(value_len),
        ),
        Some(shown) => (
            label.to_owned(),
            true,
            typing(&value, shown - label_len, value_len),
        ),
    };

    let value = cell(value_shown, value_ink);
    let value = match on_press {
        // Вид прежний: меняется только курсор.
        Some(message) => mouse_area(value)
            .on_press(message)
            .interaction(Interaction::Pointer)
            .into(),
        None => value,
    };

    Flex::row()
        .w(Size::FILL)
        .push_auto(cell(label_shown, label_ink))
        .push(filler(palette, &DOTS, dotted))
        .push_auto(value)
        .gap(CELL)
        .build()
}

/// Поток данных во всю оставшуюся высоту — `BitStream` кита.
///
/// Снизу отступ шире на [`STREAM_SKEW`]: иначе зазор под потоком выходит меньше верхнего.
fn stream<'a, Message: 'a>(load: f32) -> Element<'a, Message> {
    container(
        BitStream::new(load)
            .reveal(STREAM_REVEAL)
            .w(Size::FILL)
            .h(Size::FILL),
    )
    .padding(Padding::ZERO.bottom(STREAM_SKEW))
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

/// Заполнитель на всю пустоту; режется контейнером, поэтому край точно по окну.
fn filler<'a, Message: 'a>(
    palette: &Palette,
    glyphs: &'static str,
    shown: bool,
) -> Element<'a, Message> {
    let line = if shown { glyphs } else { "" };
    container(cell(line, ink::level(palette, ink::TERTIARY)))
        .width(Length::Fill)
        .clip(true)
        .into()
}

/// Набранная часть строки с курсором и пробелами до полной ширины.
fn typing(value: &str, shown: usize, len: usize) -> String {
    let mut out: String = value.chars().take(shown).collect();
    out.push(CURSOR);
    out.push_str(&" ".repeat(len.saturating_sub(shown + 1)));
    out
}

fn cell<'a, Message: 'a>(value: impl IntoFragment<'a>, color: Color) -> Element<'a, Message> {
    text(value)
        .size(SIZE)
        .line_height(LineHeight::Relative(1.0))
        .color(color)
        .wrapping(Wrapping::None)
        .into()
}

/// Обрезает значение по знакам, а не по байтам.
fn clip(value: &str, limit: usize) -> String {
    if count(value) <= limit {
        return value.to_owned();
    }
    let mut out: String = value.chars().take(limit.saturating_sub(1)).collect();
    out.push(CUT);
    out
}

/// Длина в знаках, не в байтах.
fn count(value: &str) -> usize {
    value.chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn palette() -> Palette {
        uikit::ThemeType::Dark.to_iced_theme().palette()
    }

    fn lines() -> Vec<Line> {
        vec![
            Line::Section("КОНФИГУРАЦИЯ".to_owned()),
            Line::Pick("ПРОФИЛЬ".to_owned(), "203.0.113.245".to_owned()),
            Line::Choice("home".to_owned(), "91 мс".to_owned(), true, 0),
            Line::Blank,
            Line::Toned("СОСТОЯНИЕ".to_owned(), "ОТКЛЮЧЕНО".to_owned(), Color::WHITE),
            Line::Stream(0.5),
            Line::Pair("СОЕДИНЕНИЙ".to_owned(), "0".to_owned()),
        ]
    }

    const PICKER: Picker<()> = Picker {
        toggle: (),
        choose: |_| (),
        scroll: |_| (),
    };

    #[test]
    fn the_console_fills_the_window() {
        let element: Element<'_, ()> = console(&palette(), &lines(), Reveal::Done, Some(&PICKER));
        let size = element.as_widget().size();

        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn typing_from_nothing_to_everything_never_panics() {
        for step in 0..=100 {
            let reveal = Reveal::Typing(step as f32 / 100.0);
            let _: Element<'_, ()> = console(&palette(), &lines(), reveal, Some(&PICKER));
        }
    }

    #[test]
    fn a_typed_line_keeps_its_width() {
        let width = count("hysteria2");
        for shown in 0..width {
            assert_eq!(
                count(&typing("hysteria2", shown, width)),
                width,
                "ширина строки поехала на {shown}-м знаке"
            );
        }
    }

    #[test]
    fn a_typed_line_shows_the_cursor_and_what_is_already_typed() {
        let shown = typing("hysteria2", 4, count("hysteria2"));
        assert!(shown.starts_with("hyst"), "набранного не видно: {shown}");
        assert!(shown.contains(CURSOR), "нет курсора: {shown}");
        assert!(!shown.contains('9'), "показано ещё не набранное: {shown}");
    }

    #[test]
    fn the_stream_takes_all_the_height_left_over() {
        let element: Element<'_, ()> = stream(0.5);
        let size = element.as_widget().size();
        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn an_idle_stream_still_holds_its_place() {
        let element: Element<'_, ()> = stream(0.0);
        assert_eq!(element.as_widget().size().height, Length::Fill);
    }

    #[test]
    fn a_long_value_is_clipped_not_pushed_off_the_edge() {
        let long = "з".repeat(200);
        let clipped = clip(&long, LIMIT);
        assert_eq!(count(&clipped), LIMIT);
        assert!(clipped.ends_with(CUT), "не сказано, что значение обрезано");
    }

    #[test]
    fn cyrillic_counts_as_one_character() {
        assert_eq!(count("СЕРВЕР"), 6);
        assert!("СЕРВЕР".len() > 6);
    }
}
