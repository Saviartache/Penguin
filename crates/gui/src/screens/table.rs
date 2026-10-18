//! Таблица терминала — одна на все экраны со списком.
//!
//! Рамки нет, есть отступ [`PANEL_PADDING`]; единственная черта — под шапкой,
//! из `─`, обрезанных контейнером по месту.
//!
//! Строка поиска стоит внутри панели, внизу, как командная строка, и отбирает
//! строки. Прокручивается только тело: шапка, подсказка и поиск стоят на месте.
//!
//! Значения выравниваются пробелами, поэтому только знаки, которые есть в
//! ZedMono (см. [`crate::console`]): дефис в [`DASH`], тильда в [`clip`].

use std::sync::LazyLock;

use iced::theme::Palette;
use iced::widget::text::{IntoFragment, LineHeight, Wrapping};
use iced::widget::{button, container, scrollable, text};
use iced::{Color, Element, Length, Padding, Theme};
use uikit::container::Wash;
use uikit::layout::{Flex, Sizable, Size, gap, px};
use uikit::scrollbar;
use uikit::tokens::{accent, ink, radius, type_scale};
use uikit::widgets::TextInput;

/// Кегль панели — как у журнала и консоли.
pub const GLYPH: f32 = type_scale::BODY;

/// Ширина знака ZedMono в долях кегля; нужна для отступов, не для столбцов.
const ADVANCE: f32 = 0.55;

/// Ширина знака в точках.
pub const CELL: f32 = GLYPH * ADVANCE;

/// Отступ от края панели до таблицы.
pub const PANEL_PADDING: f32 = CELL * 3.0;

/// Высота кнопок над панелью.
pub const BUTTON_HEIGHT: f32 = 26.0;

/// Высота строки поиска: ниже общей высоты кита, поле стоит среди строк таблицы.
const SEARCH_HEIGHT: f32 = 24.0;

/// Отступ строки. Высота числом не задаётся: `iced` кладёт содержимое кнопки в
/// левый верхний угол, и заливка уходила бы под строку.
pub const ROW_PADDING: Padding = Padding {
    top: gap::XS,
    right: gap::XS,
    bottom: gap::XS,
    left: gap::XS,
};

/// Зазор между строками списка.
pub const ROW_GAP: f32 = gap::XS;

/// Длина заполнителя кромки в знаках: длиннее любого окна, режется контейнером.
const FILLER: usize = 240;

/// Черта под шапкой таблицы.
const HORIZONTAL: char = '─';

/// Приглашение перед сообщением пустого списка.
const PROMPT: char = '>';

/// Прочерк на месте пустого значения.
pub const DASH: char = '-';

/// Сила акцента у левого края выбранной строки (волна сходит на нет вправо).
const SELECTED: f32 = 0.60;

/// То же под курсором.
const HOVERED: f32 = 0.22;

/// То же при нажатии.
const PRESSED: f32 = 0.36;

static RULE: LazyLock<String> = LazyLock::new(|| std::iter::repeat_n(HORIZONTAL, FILLER).collect());

/// Панель терминала: шапка, тело, подсказка, поиск (последним, внизу).
pub fn panel<'a, M: 'a>(
    palette: &Palette,
    search: Element<'a, M>,
    head: Element<'a, M>,
    body: Element<'a, M>,
    hint: &str,
) -> Element<'a, M> {
    frame(
        Flex::col()
            .w(Size::FILL)
            .h(Size::FILL)
            // Колонка полосы, как у строк в `scroll`: иначе столбцы шапки съезжают.
            .push_auto(container(head).padding(scrollbar::safe(0.0)))
            .push_auto(divider(palette))
            .push(body)
            // Отрыв от списка как от поля поиска: рамка поля добавляет свой.
            .push_auto(
                container(glyphs(hint.to_owned(), ink::level(palette, ink::TERTIARY)))
                    .padding(Padding::ZERO.top(gap::XS)),
            )
            .push_auto(search)
            .gap(gap::XS)
            .build(),
    )
}

/// Тот же прямоугольник без шапки и поиска — для настроек.
pub fn sheet<'a, M: 'a>(palette: &Palette, body: Element<'a, M>, hint: &str) -> Element<'a, M> {
    frame(
        Flex::col()
            .w(Size::FILL)
            .h(Size::FILL)
            .push(body)
            .push_auto(glyphs(hint.to_owned(), ink::level(palette, ink::TERTIARY)))
            .gap(gap::XS)
            .build(),
    )
}

/// Прямоугольник консоли во всю вкладку; обрезает заполнитель кромки.
fn frame<'a, M: 'a>(content: Element<'a, M>) -> Element<'a, M> {
    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(Padding::new(PANEL_PADDING))
        .style(uikit::container::log_terminal_viewport as fn(&Theme) -> _)
        .clip(true)
        .into()
}

/// Строка поиска у нижнего края панели, без приглашения слева.
pub fn search<'a, M: 'a + Clone>(
    placeholder: &'a str,
    value: &'a str,
    on_input: impl Fn(String) -> M + 'a,
) -> Element<'a, M> {
    TextInput::new(placeholder, value)
        .on_input(on_input)
        .size(GLYPH)
        .w(Size::FILL)
        .h(px(SEARCH_HEIGHT))
        .into()
}

/// Прокручиваемое тело; отступ на содержимом, иначе полоса ляжет поверх строк
/// (правило 4.6 кита).
pub fn scroll<'a, M: 'a>(list: Element<'a, M>) -> Element<'a, M> {
    scrollable(
        container(list)
            .padding(scrollbar::safe(0.0))
            .width(Length::Fill),
    )
    .direction(scrollbar::vertical())
    .style(scrollbar::style())
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

/// Пустое тело: пустая панель читается как «не загрузилось».
pub fn empty<'a, M: 'a>(palette: &Palette, reason: &str) -> Element<'a, M> {
    let line = format!("{PROMPT} {reason}");

    container(glyphs(line, ink::level(palette, ink::TERTIARY)))
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(gap::SM)
        .into()
}

/// Кнопка действия в конце строки; ширина числом, чтобы не двигать заголовок соседнего столбца.
pub fn action<'a, M: 'a + Clone>(label: &str, width: f32, on_press: M) -> Element<'a, M> {
    button(
        container(
            text(format!("[{label}]"))
                .size(GLYPH)
                .line_height(LineHeight::Relative(1.0))
                .wrapping(Wrapping::None),
        )
        .center_x(Length::Fill),
    )
    .width(Length::Fixed(width))
    .padding(ROW_PADDING)
    .style(uikit::button::ghost)
    .on_press(on_press)
    .into()
}

/// Черта во всю ширину — под шапкой и за заголовком раздела.
pub fn divider<'a, M: 'a>(palette: &Palette) -> Element<'a, M> {
    container(glyphs(&**RULE, ink::level(palette, ink::TERTIARY)))
        .width(Length::Fill)
        .clip(true)
        .into()
}

/// Вид строки: акцентная волна от левого края, сходящая на нет вправо.
pub fn row_style(selected: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        let palette = theme.palette();
        let strength = match (selected, status) {
            // Выбранная строка может быть недоступной для нажатия, но выглядит выбранной.
            (true, _) => SELECTED,
            (false, button::Status::Hovered) => HOVERED,
            (false, button::Status::Pressed) => PRESSED,
            (false, _) => 0.0,
        };

        if strength <= 0.0 {
            return button::Style {
                text_color: palette.text,
                ..button::Style::default()
            };
        }

        // Волна общая с контейнером кита.
        let wave = uikit::container::washed(
            Color::TRANSPARENT,
            accent::wash(&palette, strength),
            Wash::FromLeft,
            radius::CONTROL,
        );

        button::Style {
            background: wave.background,
            border: wave.border,
            text_color: palette.text,
            ..button::Style::default()
        }
    }
}

/// Знаки панели: кегль, цвет, без переноса; шрифт — умолчание окна.
pub fn glyphs<'a, M: 'a>(value: impl IntoFragment<'a>, color: Color) -> Element<'a, M> {
    text(value)
        .size(GLYPH)
        .line_height(LineHeight::Relative(1.0))
        .color(color)
        .wrapping(Wrapping::None)
        .into()
}

/// Дополняет строку пробелами до ширины столбца.
pub fn pad(value: &str, width: usize) -> String {
    let tail = width.saturating_sub(value.chars().count());
    let mut out = String::with_capacity(value.len() + tail);
    out.push_str(value);
    out.extend(std::iter::repeat_n(' ', tail));
    out
}

/// То же слева: значение встаёт по правому краю столбца.
pub fn lpad(value: &str, width: usize) -> String {
    let head = width.saturating_sub(value.chars().count());
    let mut out = String::with_capacity(value.len() + head);
    out.extend(std::iter::repeat_n(' ', head));
    out.push_str(value);
    out
}

/// Обрезает по знакам, не по байтам; хвост помечен тильдой (есть в шрифте кита).
pub fn clip(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_owned();
    }
    let mut out: String = value.chars().take(width.saturating_sub(1)).collect();
    out.push('~');
    out
}

/// Обрезает и дополняет разом.
pub fn cell(value: &str, width: usize) -> String {
    pad(&clip(value, width), width)
}

/// Подходит ли строка под поиск: по всем полям; пустой запрос пропускает всё.
pub fn matches(query: &str, fields: &[&str]) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }

    fields
        .iter()
        .any(|field| field.to_lowercase().contains(&query))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_keep_their_width() {
        assert_eq!(pad("source", 18).chars().count(), 18);
        assert_eq!(pad("", 18).chars().count(), 18);
        assert_eq!(lpad("90 мс", 8).chars().count(), 8);
        assert_eq!(cell("hysteria2", 12).chars().count(), 12);
    }

    #[test]
    fn a_value_at_the_right_edge_is_padded_on_the_left() {
        assert!(lpad("42 мс", 8).starts_with("   "));
        assert!(lpad("42 мс", 8).ends_with("42 мс"));
    }

    #[test]
    fn a_long_value_is_clipped_not_pushed_through() {
        let long = "и".repeat(100);
        assert_eq!(clip(&long, 18).chars().count(), 18);
        assert!(clip(&long, 18).ends_with('~'));
        assert_eq!(cell(&long, 18).chars().count(), 18);
    }

    #[test]
    fn a_value_that_fits_is_left_alone() {
        assert_eq!(clip("source", 18), "source");
    }

    #[test]
    fn an_empty_query_keeps_every_row() {
        assert!(matches("", &["что угодно"]));
        assert!(matches("   ", &["что угодно"]));
    }

    #[test]
    fn search_looks_at_every_field_of_a_row() {
        let row = ["Дом", "example.com:443", "hysteria2"];
        assert!(matches("дом", &row));
        assert!(matches("EXAMPLE", &row));
        assert!(matches("hyst", &row));
        assert!(!matches("нет такого", &row));
    }

    #[test]
    fn the_fill_sits_evenly_around_the_row() {
        assert_eq!(ROW_PADDING.top, ROW_PADDING.bottom);
    }

    #[test]
    fn the_panel_fills_the_tab() {
        let palette = uikit::ThemeType::Dark.to_iced_theme().palette();
        let built: Element<'_, ()> = panel(
            &palette,
            glyphs(String::new(), Color::WHITE),
            glyphs(String::new(), Color::WHITE),
            scroll(glyphs("строка".to_owned(), Color::WHITE)),
            "ПОДСКАЗКА",
        );

        let size = built.as_widget().size();
        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }
}
