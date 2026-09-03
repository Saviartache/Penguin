//! Таблица терминала — одна на все экраны, где есть список.
//!
//! Раньше она жила внутри экрана серверов. Второй такой же список — правила —
//! означал бы второй набор тех же констант, и разойтись им ничто бы не мешало:
//! столбец, съехавший на знак относительно шапки, — единственное, что видно в
//! таблице, а два похожих файла рядом расходятся сами собой.
//!
//! # Рамки нет, есть отступ
//!
//! Панель — прямоугольник консоли, и таблица начинается сразу. Рамка из знаков
//! вокруг неё обводила то, что и так очерчено фоном, и отнимала строку сверху и
//! снизу. Границу держит отступ [`PANEL_PADDING`] — он же не даёт столбцам
//! упереться в край.
//!
//! Единственная черта, которая осталась, — под шапкой: она отделяет имена
//! столбцов от значений, а не обводит панель. Набрана заполнителем из `─`,
//! обрезанным контейнером по месту: знаки не считаются, и правый край черты
//! приходится ровно на край панели при любой ширине окна.
//!
//! # Поиск и прокрутка
//!
//! Строка поиска стоит **внутри** панели, в самом низу, под всем остальным, и
//! отбирает строки, а не прячет столбцы: список из тридцати правил читают не
//! подряд, а по одному имени, которое помнят. Внизу, а не над шапкой, потому
//! что это командная строка терминала, а не заголовок формы: сверху она
//! отодвигала бы вниз имена столбцов — то, с чего таблицу начинают читать.
//!
//! Прокручивается при этом только тело таблицы — заголовки столбцов, подсказка
//! и поиск стоят на месте, как в окне терминала. Поэтому же панель растянута по
//! обеим осям: страницы с прокруткой вокруг неё нет, и уехать за нижний край
//! окну нечем.
//!
//! # Только те знаки, которые в шрифте есть
//!
//! Значения выравниваются пробелами, а не мерой текста, и потому знак, которого
//! в ZedMono нет, ломает столбец: `iced` берёт такой знак из системного шрифта,
//! а там он шириной в кегль, а не в ячейку (см. [`crate::console`]). Отсюда
//! дефис вместо длинного тире в [`DASH`] и тильда вместо многоточия в
//! [`clip`].

use iced::theme::Palette;
use iced::widget::text::{LineHeight, Wrapping};
use iced::widget::{button, container, scrollable, text};
use iced::{Color, Element, Length, Padding, Theme};
use uikit::layout::{Flex, Sizable, Size, gap, px};
use uikit::style::container::Wash;
use uikit::style::scrollbar;
use uikit::style::tokens::{accent, ink, radius, type_scale};
use uikit::widgets::TextInput;

/// Кегль панели — тот же, что у строки журнала и у консоли главного экрана.
pub const GLYPH: f32 = type_scale::BODY;

/// Ширина знака в долях кегля.
///
/// У встроенного ZedMono знак узкий — около половины кегля. Точное значение
/// знает только шрифт, и здесь оно нужно ровно для отступов: раскладку
/// столбцов держат пробелы внутри строк, а не эта оценка.
const ADVANCE: f32 = 0.55;

/// Ширина знака в точках.
pub const CELL: f32 = GLYPH * ADVANCE;

/// Отступ от края панели до таблицы.
///
/// Три знака: столбец, прижатый к краю прямоугольника, читается как обрезанный.
/// Слева к нему добавляется отступ строки — на него заходит заливка выбранной,
/// и без него она упиралась бы в первую букву.
pub const PANEL_PADDING: f32 = CELL * 3.0;

/// Высота кнопок над панелью.
pub const BUTTON_HEIGHT: f32 = 26.0;

/// Высота строки поиска.
///
/// Ниже общей высоты элементов управления кита: поиск стоит внутри панели, в
/// ряду со строками таблицы, и поле в тридцать шесть точек читалось бы там
/// формой из другого окна.
const SEARCH_HEIGHT: f32 = 24.0;

/// Отступ строки: одинаковый сверху и снизу, по знаку слева и справа.
///
/// Высота строки числом **не** задаётся, и это не мелочь: `iced` кладёт
/// содержимое кнопки в левый верхний угол отведённого места, а не в середину
/// (`layout::padded`). Заданная высота при строке текста вдвое ниже уводила
/// заливку под строку на весь остаток. Высоту даёт содержимое, а поровну
/// сверху и снизу её добирает этот отступ — тогда заливка обнимает строку и
/// разъехаться с ней не может.
pub const ROW_PADDING: Padding = Padding {
    top: gap::XS,
    right: gap::XS,
    bottom: gap::XS,
    left: gap::XS,
};

/// Зазор между строками списка.
///
/// Строки — это строки таблицы, а не отдельные карточки: зазор отделяет одну
/// заливку от другой и не больше. Больший рассыпал бы столбец на несвязанные
/// значения.
pub const ROW_GAP: f32 = gap::XS;

/// Длина заполнителя кромки в знаках.
///
/// Нарочно длиннее любого окна: правый край заполнителя приходится на край
/// панели потому, что лишнее обрезано, а не потому, что число подобрано.
const FILLER: usize = 240;

/// Черта под шапкой таблицы.
const HORIZONTAL: char = '─';

/// Приглашение перед сообщением пустого списка.
const PROMPT: char = '>';

/// Прочерк на месте пустого значения.
pub const DASH: char = '-';

/// Сила акцента у левого края выбранной строки.
///
/// Заметно выше ступеней `state::TINT_*`: те заливают строку ровно, а здесь
/// акцент сходит на нет к правому краю, и головка такой же силы читалась бы
/// вдвое тише самой заливки.
const SELECTED: f32 = 0.60;

/// То же под курсором на невыбранной строке.
const HOVERED: f32 = 0.22;

/// То же в момент нажатия.
const PRESSED: f32 = 0.36;

/// Панель терминала целиком: шапка, тело, подсказка, поиск.
///
/// Поиск последний — командная строка внизу окна терминала; см. заметку о
/// поиске в начале модуля.
///
/// Растянута по обеим осям и обрезает содержимое: заполнитель кромки нарочно
/// длиннее любого окна, и без отсечения он вылез бы за прямоугольник панели.
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
            .push_auto(head)
            .push_auto(divider(palette))
            .push(body)
            .push_auto(glyphs(hint.to_owned(), ink::level(palette, ink::TERTIARY)))
            .push_auto(search)
            .gap(gap::XS)
            .build(),
    )
}

/// Тот же прямоугольник консоли, но без шапки и без поиска.
///
/// Для экрана, у которого нет столбцов и нечего искать: настройки — это четыре
/// переключателя, а не список записей. Шапка над ними называла бы столбцы,
/// которых нет, а поиск по четырём строкам — элемент управления, который никто
/// не тронет.
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

/// Прямоугольник консоли во всю вкладку.
///
/// Обрезает содержимое: заполнитель кромки нарочно длиннее любого окна, и без
/// отсечения он вылез бы за прямоугольник панели.
fn frame<'a, M: 'a>(content: Element<'a, M>) -> Element<'a, M> {
    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(Padding::new(PANEL_PADDING))
        .style(uikit::style::container::log_terminal_viewport as fn(&Theme) -> _)
        .clip(true)
        .into()
}

/// Строка поиска у нижнего края панели.
///
/// Одно поле во всю ширину, без приглашения `>` слева: место, где ждут ввода,
/// у поля обозначено им самим — рамкой и подсказкой внутри, — а знак перед ним
/// повторял бы это второй раз и отодвигал бы поле от края панели, к которому
/// прижато всё остальное.
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

/// Прокручиваемое тело таблицы.
///
/// Отступ — на содержимом прокрутки, а не на обёртке: иначе полоса ляжет
/// поверх строк у правого края (правило 4.6 кита).
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

/// Пустое тело таблицы: почему здесь ничего нет.
///
/// Пустая панель читается как «не загрузилось», и человек ждёт.
pub fn empty<'a, M: 'a>(palette: &Palette, reason: &str) -> Element<'a, M> {
    let line = format!("{PROMPT} {reason}");

    container(glyphs(line, ink::level(palette, ink::TERTIARY)))
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(gap::SM)
        .into()
}

/// Кнопка действия в конце строки — подпись в скобках, как пункт меню
/// терминала.
///
/// Ширина задаётся числом, а не подписью: над столбцом действия стоит
/// заголовок соседнего столбца, и подпись, которая на другом языке короче,
/// увела бы заголовок от значений.
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
    // Тот же отступ, что у строки: иначе кнопка ниже строки, и подпись стоит
    // не на её линии.
    .padding(ROW_PADDING)
    .style(uikit::style::button::ghost)
    .on_press(on_press)
    .into()
}

/// Черта во всю оставшуюся ширину — под шапкой таблицы и за заголовком раздела.
///
/// Нарочно длиннее любого окна и обрезается контейнером — так её правый край
/// приходится ровно на край панели, а не на подобранное на глаз число знаков.
pub fn divider<'a, M: 'a>(palette: &Palette) -> Element<'a, M> {
    let line: String = std::iter::repeat_n(HORIZONTAL, FILLER).collect();

    container(glyphs(line, ink::level(palette, ink::TERTIARY)))
        .width(Length::Fill)
        .clip(true)
        .into()
}

/// Вид строки: акцентная волна от левого края, сходящая на нет вправо.
///
/// Волна, а не ровная заливка: ровная превращает строку в плашку, и список из
/// них читается как решётка. Волна помечает начало строки и отпускает
/// последний столбец у правого края.
pub fn row_style(selected: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        let palette = theme.palette();
        let strength = match (selected, status) {
            // Выбранная строка нажатия может не принимать, и `iced` считает её
            // недоступной; выглядеть она обязана выбранной.
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

        // Волна берётся у кита целиком: у контейнера и у кнопки она обязана
        // быть одной и той же, а второй такой градиент разошёлся бы с первым.
        let wave = uikit::style::container::washed(
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

/// Знаки панели: кегль, цвет, без переноса.
///
/// Шрифт не задаётся: он один на всё окно и приходит умолчанием (см.
/// [`crate::ui::FONT`]).
pub fn glyphs<'a, M: 'a>(value: String, color: Color) -> Element<'a, M> {
    text(value)
        .size(GLYPH)
        // Ровно кегль: запас между строками стоит снаружи, в зазоре группы.
        .line_height(LineHeight::Relative(1.0))
        .color(color)
        // Без переноса: строка таблицы — это строка, а не абзац.
        .wrapping(Wrapping::None)
        .into()
}

/// Дополняет строку пробелами до ширины столбца.
///
/// Свободная функция с тестом: столбец, съехавший на знак, — единственное, что
/// видно в таблице, и последнее, что находится глазами в коде.
pub fn pad(value: &str, width: usize) -> String {
    let tail = width.saturating_sub(value.chars().count());
    format!("{value}{}", " ".repeat(tail))
}

/// То же, но пробелы слева: значение встаёт по правому краю столбца.
pub fn lpad(value: &str, width: usize) -> String {
    let head = width.saturating_sub(value.chars().count());
    format!("{}{value}", " ".repeat(head))
}

/// Обрезает строку по знакам, а не по байтам.
///
/// Хвост помечен тильдой: так DOS укорачивал длинные имена (`PROGRA~1`), и, в
/// отличие от многоточия, тильда в моноширинном шрифте кита есть наверняка —
/// значит, займёт ровно знак и не сдвинет за собой столбец.
pub fn clip(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_owned();
    }
    value
        .chars()
        .take(width.saturating_sub(1))
        .collect::<String>()
        + "~"
}

/// Обрезает и дополняет разом — то, что нужно ячейке таблицы.
pub fn cell(value: &str, width: usize) -> String {
    pad(&clip(value, width), width)
}

/// Подходит ли строка под поиск.
///
/// Ищет по всем полям строки, а не по одному: человек помнит либо имя, либо
/// адрес, либо то, что правило делает, — и заранее не знает, что именно
/// вспомнит. Пустой запрос пропускает всё: поиск, отбирающий на пустом поле, —
/// это исчезнувший список.
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
        // Таблицу читают по столбцам; съехавший на знак столбец рушит весь
        // смысл затеи.
        assert_eq!(pad("source", 18).chars().count(), 18);
        assert_eq!(pad("", 18).chars().count(), 18);
        assert_eq!(lpad("90 мс", 8).chars().count(), 8);
        assert_eq!(cell("hysteria2", 12).chars().count(), 12);
    }

    #[test]
    fn a_value_at_the_right_edge_is_padded_on_the_left() {
        // Цифры сравнивают по разрядам, а разряды совпадают только у значений,
        // выровненных вправо.
        assert!(lpad("42 мс", 8).starts_with("   "));
        assert!(lpad("42 мс", 8).ends_with("42 мс"));
    }

    #[test]
    fn a_long_value_is_clipped_not_pushed_through() {
        // Иначе длинное значение сдвинуло бы за собой все остальные столбцы.
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
        // Поиск, отбирающий на пустом поле, — это исчезнувший список.
        assert!(matches("", &["что угодно"]));
        assert!(matches("   ", &["что угодно"]));
    }

    #[test]
    fn search_looks_at_every_field_of_a_row() {
        // Человек помнит либо имя, либо адрес, либо то, что правило делает.
        let row = ["Дом", "example.com:443", "hysteria2"];
        assert!(matches("дом", &row));
        assert!(matches("EXAMPLE", &row));
        assert!(matches("hyst", &row));
        assert!(!matches("нет такого", &row));
    }

    #[test]
    fn the_fill_sits_evenly_around_the_row() {
        // Высота строки задавалась числом, а `iced` кладёт содержимое кнопки в
        // левый верхний угол, а не в середину: заливка уходила под строку на
        // весь остаток.
        assert_eq!(ROW_PADDING.top, ROW_PADDING.bottom);
    }

    #[test]
    fn the_panel_fills_the_tab() {
        // Панель — окно терминала: прокручивается тело внутри неё, а сама она
        // стоит на месте. Страницы с прокруткой вокруг больше нет.
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
