//! Консольное окно главного экрана — вывод DOS, а не карточка.
//!
//! Раньше здесь рисовалась символьная рамка: панель была одной строкой текста, а
//! её ширина считалась в знаках. Так она и не могла достать до края окна —
//! ширина окна задана в точках, ширина знака зависит от шрифта, и совпасть они
//! могли только случайно. Отсюда нынешнее устройство: рамки нет, каждая строка —
//! ряд виджетов, а пустоту между полем и значением растягивает контейнер. Ширину
//! в знаках больше не считает никто, и консоль занимает всё окно при любом
//! шрифте и любом масштабе.
//!
//! Язык взят у вывода `MEM` и `CHKDSK`: заглавные подписи слева, значения у
//! правого края, точки между ними, заголовок раздела с чертой до края,
//! приглашение с мигающим блоком внизу. Что это дало помимо точности:
//!
//! - у каждой строки свой цвет — поле приглушено, значение ярко, состояние идёт
//!   своим тоном. Одной строкой текста так было нельзя;
//! - печать при первом открытии идёт по знакам, но место под строку заготовлено
//!   заранее: недобранное занято пробелами, поэтому точки и значения не
//!   дёргаются на каждом знаке;
//! - курсор мигает, а не стоит.
//!
//! Отступ от края одинаковый со всех четырёх сторон — см. [`PAD`].
//!
//! # Только те знаки, которые в шрифте есть
//!
//! Значение встаёт по правому краю **измеренной** шириной текста. Знака, которого
//! в шрифте кита нет, `iced` берёт из системного, а там он шириной в кегль, а не
//! в знак: нарисованное оказывается шире измеренного, и значение вылезает за
//! правый край. Ровно так уезжало длинное тире в строке задержки — единственная
//! строка, где ровный край консоли ломался.
//!
//! Отсюда правило на весь экран: в подписях и значениях консоли — только то, что
//! в ZedMono есть наверняка. ASCII, кириллица, рамочные и блочные знаки (`─`,
//! `▁`..`█`) есть; длинное тире, многоточие и прочая типографика — под вопросом,
//! и потому прочерк здесь дефис ([`crate::screens::compact`]), а обрезанный
//! хвост помечен тильдой ([`CUT`]).

use iced::theme::Palette;
use iced::widget::text::{LineHeight, Wrapping};
use iced::widget::{Space, container, text};
use iced::{Color, Element, Length, Padding};
use uikit::layout::{Flex, Sizable, Size, px};
use uikit::style::tokens::{ink, type_scale};

/// Кегль консоли.
const SIZE: f32 = type_scale::BODY;

/// Высота строки текста — ровно кегль.
///
/// Межстрочного интервала внутри строки нет намеренно. Он был: строка занимала
/// кегль с третью, и лишняя треть стояла внутри неё невидимым запасом. Пока
/// соседи — такие же строки, зазор выходит одинаковым сам собой, но графику
/// пришлось задать отступ отдельным числом, и совпасть эти два числа могли только
/// случайно — отсюда и разъехавшиеся зазоры вокруг графика.
///
/// Поэтому запас вынесен наружу, в [`SPACING`]: теперь между **любыми** двумя
/// строками консоли стоит одно и то же расстояние, и график в этом смысле такая
/// же строка, как остальные.
const LINE: f32 = SIZE;

/// Единственный зазор консоли — между любыми двумя строками, включая график.
///
/// Треть кегля: столько занимал межстрочный интервал текстового режима. Шаг
/// строки от этого не изменился — он по-прежнему кегль с третью, только теперь
/// треть видна в раскладке, а не спрятана внутри строки.
const SPACING: f32 = SIZE / 3.0;

/// Ширина знака относительно кегля.
///
/// У встроенного ZedMono знак узкий — около половины кегля. Точное значение
/// знает только шрифт, и здесь оно нужно ровно для одного: отступа от края и
/// зазора между полем и значением. Промах в полпиксела там не значит ничего —
/// раскладку строк он не трогает, её растягивает контейнер.
const ADVANCE: f32 = 0.55;

/// Ширина знака в точках.
const CELL: f32 = SIZE * ADVANCE;

/// Отступ консоли от края — одинаковый со всех четырёх сторон.
///
/// Сверху и снизу это была высота строки: в знаках столько же, сколько знак
/// шириной по бокам, но глазу — втрое больше, и верх читался как провал перед
/// первой строкой. Поэтому отступ один на все стороны, и по бокам он с запасом:
/// значение, прижатое к самому краю, читается как вылезшее за него.
const PAD: f32 = CELL * 2.0;

/// Курсор.
const CURSOR: char = '█';

/// Точки между полем и значением.
///
/// Точка, а не средняя точка: так расставлял их `MEM`, и так они читаются
/// строкой, ведущей глаз от подписи к цифре.
const LEADER: char = '.';

/// Черта в заголовке раздела.
const DASH: char = '─';

/// Зазор между столбиками графика.
///
/// Один пиксел: столбик шириной в несколько пикселов, разделённый большим
/// зазором, перестаёт читаться как столбик и становится точкой.
const BAR_GAP: f32 = 1.0;

/// Толщина оси — черты под столбиками.
///
/// Пиксел: ось показывает, где у графика низ, и не должна выглядеть как самый
/// короткий столбик.
const AXIS: f32 = 1.0;

/// На сколько ступеней делится высота графика.
///
/// Доля столбика берётся местом в колонке, а не числом знаков, поэтому ступеней
/// столько, сколько нужно для плавности, — высота графика в пикселах тут ни при
/// чём.
const STEPS: u16 = 100;

/// Длина заполнителя в знаках.
///
/// Точки и черта обрезаются контейнером по месту, поэтому заполнителю нужно
/// лишь с запасом перекрыть самое широкое окно.
const FILLER: usize = 240;

/// Предел длины значения в знаках.
///
/// Не раскладка, а страховка: раскладку считает контейнер, а это защита от имени
/// профиля на двести знаков, которое выдавило бы за край всё остальное.
const LIMIT: usize = 48;

/// Одна строка консоли.
///
/// Обе половины строки — свои: экран собирает подписи на ходу (приводит к
/// верхнему регистру, дописывает время работы), и держать их взаймы значило бы
/// заводить переменную под каждую подпись на стороне экрана.
pub enum Line {
    /// Заголовок раздела: имя и черта до правого края.
    Section(String),
    /// Поле и значение, точки между ними до правого края.
    Pair(String, String),
    /// То же, но значение своим цветом — состояние тоннеля.
    Toned(String, String, Color),
    /// Столбчатый график по долям от нуля до единицы.
    ///
    /// Единственная строка, которой достаётся место: она забирает всю высоту,
    /// не занятую текстом, и потому идёт ровно одна на экран. Пустых
    /// строк-разделителей в консоли поэтому и нет — свободную высоту держит
    /// график, а блоки делит черта в заголовке раздела.
    Graph(Vec<f32>),
    /// Приглашение с курсором.
    Prompt(String),
}

/// Сколько консоли показывать.
#[derive(Debug, Clone, Copy)]
pub enum Reveal {
    /// Напечатано всё.
    Done {
        /// Виден ли курсор в этот момент — он мигает.
        cursor: bool,
    },
    /// Печатается: доля напечатанного, `0.0..=1.0`.
    Typing(f32),
}

/// Собирает консоль во всё окно.
pub fn console<'a, Message: 'a>(
    palette: &Palette,
    lines: &[Line],
    reveal: Reveal,
) -> Element<'a, Message> {
    let total: usize = lines.iter().map(cost).sum();
    let (typed, cursor) = match reveal {
        Reveal::Done { cursor } => (total, cursor),
        // Пока печатается, курсор ставит сама набираемая строка.
        Reveal::Typing(fraction) => {
            let fraction = fraction.clamp(0.0, 1.0);
            (((total as f32) * fraction).ceil() as usize, false)
        }
    };

    let mut body = Flex::col().w(Size::FILL).h(Size::FILL).gap(SPACING);
    let mut at = 0;
    for line in lines {
        let end = at + cost(line);
        // До строки ещё не дошли — её просто нет: так она и появляется, сверху
        // вниз, а не проявляется из пустоты на своём месте.
        let shown = if typed >= end {
            Some(draw(palette, line, None, cursor))
        } else if typed > at {
            Some(draw(palette, line, Some(typed - at), cursor))
        } else {
            None
        };
        at = end;

        if let Some(element) = shown {
            body = match line {
                // Единственная строка, которой достаётся место, — она его и
                // забирает целиком.
                Line::Graph(_) => body.push(element),
                // Высота задаётся здесь, а не оставляется на усмотрение строки:
                // строка из точек и строка из чёрточек мерятся каждая своим
                // шрифтом, и одинаковыми они выходят только пока об этом никто
                // не спрашивал. Заданная высота делает шаг строки одним на весь
                // экран.
                _ => body.push_sized(element, px(LINE)),
            };
        }
    }

    container(body.build())
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(Padding::new(PAD))
        .style(uikit::style::container::log_terminal_viewport as fn(&iced::Theme) -> _)
        // Заполнители нарочно длиннее окна; без отсечения они вылезли бы за
        // тёмный прямоугольник.
        .clip(true)
        .into()
}

/// Сколько знаков «набирается» в строке.
///
/// Свободная функция: от неё зависит, ровно ли идёт печать. Строка из одного
/// поля не должна проскакивать незаметно, а пустая — задерживать надолго.
fn cost(line: &Line) -> usize {
    match line {
        Line::Pair(label, value) | Line::Toned(label, value, _) => count(label) + count(value),
        Line::Section(label) | Line::Prompt(label) => count(label),
        // График — данные, а не набранный текст: он появляется целиком.
        Line::Graph(_) => 0,
    }
}

/// Рисует строку. `typed` — сколько её знаков набрано; `None` — набрана вся.
fn draw<'a, Message: 'a>(
    palette: &Palette,
    line: &Line,
    typed: Option<usize>,
    cursor: bool,
) -> Element<'a, Message> {
    let dim = ink::level(palette, ink::SECONDARY);
    match line {
        Line::Section(label) => section(palette, label, typed),
        Line::Pair(label, value) => duo(palette, label, value, dim, palette.text, typed),
        Line::Toned(label, value, tone) => duo(palette, label, value, dim, *tone, typed),
        Line::Graph(points) => graph(palette, points),
        Line::Prompt(prompt) => prompt_line(palette, prompt, typed, cursor),
    }
}

/// Заголовок раздела: имя и черта до правого края.
fn section<'a, Message: 'a>(
    palette: &Palette,
    label: &str,
    typed: Option<usize>,
) -> Element<'a, Message> {
    let length = count(label);
    let (shown, ruled) = match typed {
        None => (label.to_owned(), true),
        // Черта дорисовывается, когда имя набрано: иначе она тянулась бы от
        // первой же буквы, и заголовок читался бы задом наперёд.
        Some(shown) => (typing(label, shown, length), false),
    };

    Flex::row()
        .w(Size::FILL)
        .push_auto(cell(shown, palette.text))
        .push(filler(palette, DASH, ruled))
        .gap(CELL)
        .build()
}

/// Строка из поля и значения: поле слева, значение у правого края.
///
/// Пустоту между ними растягивает контейнер, поэтому значение стоит ровно у
/// края при любой ширине окна.
fn duo<'a, Message: 'a>(
    palette: &Palette,
    label: &str,
    value: &str,
    label_ink: Color,
    value_ink: Color,
    typed: Option<usize>,
) -> Element<'a, Message> {
    let value = clip(value, LIMIT);
    let (label_len, value_len) = (count(label), count(&value));
    let (label_shown, dotted, value_shown) = match typed {
        None => (label.to_owned(), true, value.clone()),
        // Набирается поле: значения ещё нет, но место под него уже занято
        // пробелами — иначе точки поехали бы вправо на каждом знаке.
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

    Flex::row()
        .w(Size::FILL)
        .push_auto(cell(label_shown, label_ink))
        .push(filler(palette, LEADER, dotted))
        .push_auto(cell(value_shown, value_ink))
        .gap(CELL)
        .build()
}

/// Столбчатый график во всю оставшуюся высоту.
///
/// Столбики, а не блочные знаки: знаками высота графика ограничена одной строкой
/// и восемью ступенями внутри неё. Здесь высота — это всё место, что осталось от
/// текста, ступеней столько, сколько задано [`STEPS`], и график читается как
/// график, а не как «что-то идёт».
///
/// Свежий отсчёт — справа: слева уезжает старое, как на любом графике времени.
/// Сколько отсчётов рисовать, решает вызывающий: он знает, какую историю держит,
/// а здесь рисуются все, что дали.
fn graph<'a, Message: 'a>(palette: &Palette, points: &[f32]) -> Element<'a, Message> {
    let bars = points.iter().map(|point| bar(palette.primary, *point));

    let bars = Flex::row()
        .w(Size::FILL)
        .h(Size::FILL)
        .extend(bars)
        .gap(BAR_GAP)
        .build();

    // Своего отступа у графика нет: зазор сверху и снизу ему даёт колонка — тот
    // же, что и между строками текста. Ось идёт внутри графика, а не отдельной
    // строкой консоли: это его низ, а не сообщение рядом с ним.
    Flex::col()
        .w(Size::FILL)
        .h(Size::FILL)
        .push(bars)
        .push_auto(axis(palette))
        .build()
}

/// Ось графика — черта, по которой стоят столбики.
///
/// Без неё низ графика не виден вовсе: отсчёт «ничего не шло» — это столбик
/// толщиной в пиксел, и в тёмной консоли он теряется, а вместе с ним теряется
/// и то, откуда столбики растут.
fn axis<'a, Message: 'a>(palette: &Palette) -> Element<'a, Message> {
    let color = ink::level(palette, ink::TERTIARY);

    container(Space::new())
        .width(Length::Fill)
        .height(Length::Fixed(AXIS))
        .style(move |_: &iced::Theme| container::Style {
            background: Some(color.into()),
            // По сетке пикселов: черта толщиной в пиксел, размазанная между
            // двумя, — это полупрозрачная черта толщиной в два.
            snap: true,
            ..container::Style::default()
        })
        .into()
}

/// Один столбик: пустота сверху, залитая доля снизу.
///
/// Доля берётся местом в колонке, а не пикселами: высоту графика знает только
/// раскладка, и считать её здесь значило бы считать её дважды.
fn bar<'a, Message: 'a>(color: Color, share: f32) -> Element<'a, Message> {
    // Не ноль: столбик нулевой высоты — это квад нулевого размера, которого не
    // принимает отрисовщик, и вдобавок пропавшая с графика точка. Отсчёт «ничего
    // не шло» обязан быть виден основанием.
    let filled = ((share.clamp(0.0, 1.0) * f32::from(STEPS)).round() as u16).clamp(1, STEPS);

    let body = container(Space::new())
        .width(Length::Fill)
        .height(Length::FillPortion(filled))
        .style(move |_: &iced::Theme| container::Style {
            background: Some(color.into()),
            // По сетке пикселов: столбик в четыре пиксела шириной, размазанный
            // между пятью, теряет и цвет, и края.
            snap: true,
            ..container::Style::default()
        });

    let mut column = iced::widget::Column::new()
        .width(Length::Fill)
        .height(Length::Fill);
    // Пустоты нет вовсе, когда столбик во всю высоту: `FillPortion(0)` схлопнул
    // бы колонку в ноль.
    if filled < STEPS {
        column = column.push(Space::new().height(Length::FillPortion(STEPS - filled)));
    }
    column.push(body).into()
}

/// Приглашение с курсором.
fn prompt_line<'a, Message: 'a>(
    palette: &Palette,
    prompt: &str,
    typed: Option<usize>,
    cursor: bool,
) -> Element<'a, Message> {
    let shown = match typed {
        // Место под курсор занято всегда: мигая, он не должен двигать строку.
        None if cursor => format!("{prompt}{CURSOR}"),
        None => format!("{prompt} "),
        Some(shown) => typing(prompt, shown, count(prompt)),
    };
    cell(shown, palette.text)
}

/// Заполнитель на всю оставшуюся пустоту: точки, черта, ровная линия.
///
/// Он нарочно длиннее любого окна и обрезается контейнером — так его правый край
/// приходится ровно на край окна, а не на подобранное на глаз число знаков.
fn filler<'a, Message: 'a>(palette: &Palette, glyph: char, shown: bool) -> Element<'a, Message> {
    let line = if shown {
        std::iter::repeat_n(glyph, FILLER).collect()
    } else {
        String::new()
    };
    container(cell(line, ink::level(palette, ink::TERTIARY)))
        .width(Length::Fill)
        .clip(true)
        .into()
}

/// Набранная часть строки с курсором и запасом пробелов до полной ширины.
///
/// Свободная функция с тестом: без запаса ширина строки менялась бы на каждом
/// знаке, и раскладка дёргалась бы вместе с ней.
fn typing(value: &str, shown: usize, len: usize) -> String {
    let mut out: String = value.chars().take(shown).collect();
    out.push(CURSOR);
    out.push_str(&" ".repeat(len.saturating_sub(shown + 1)));
    out
}

/// Знаки консоли: кегль, интервал, цвет, без переноса.
fn cell<'a, Message: 'a>(value: String, color: Color) -> Element<'a, Message> {
    text(value)
        .size(SIZE)
        // Ровно кегль: запас между строками стоит снаружи, в зазоре колонки.
        .line_height(LineHeight::Relative(1.0))
        .color(color)
        // Без переноса: строка консоли — это строка, а не абзац.
        .wrapping(Wrapping::None)
        .into()
}

/// Знак на месте обрезанного хвоста.
///
/// Тильда, а не многоточие: так DOS укорачивал длинные имена (`PROGRA~1`), и,
/// в отличие от многоточия, тильда есть в моноширинном шрифте кита — значит
/// займёт ровно знак и не вылезет за правый край (см. [`SAFE`]).
const CUT: char = '~';

/// Обрезает значение по знакам, а не по байтам.
fn clip(value: &str, limit: usize) -> String {
    if count(value) <= limit {
        return value.to_owned();
    }
    let mut out: String = value.chars().take(limit.saturating_sub(1)).collect();
    out.push(CUT);
    out
}

/// Длина в знаках.
///
/// Не в байтах: русская буква занимает два, и запас пробелов вышел бы вдвое
/// длиннее нужного.
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
            Line::Pair("ПРОФИЛЬ".to_owned(), "84.22.150.245".to_owned()),
            Line::Toned("СОСТОЯНИЕ".to_owned(), "ОТКЛЮЧЕНО".to_owned(), Color::WHITE),
            Line::Graph(vec![0.0, 0.5, 1.0]),
            Line::Prompt("C:\\OSTRIACKI> ".to_owned()),
        ]
    }

    #[test]
    fn the_console_fills_the_window() {
        // Ради этого рамку и убрали: её ширина считалась в знаках и до края
        // окна не доставала.
        let element: Element<'_, ()> = console(&palette(), &lines(), Reveal::Done { cursor: true });
        let size = element.as_widget().size();

        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn typing_from_nothing_to_everything_never_panics() {
        // Каждая доля — своя раскладка строк, и пропущенный край здесь означает
        // падение на живом окне ровно один раз: при открытии.
        for step in 0..=100 {
            let reveal = Reveal::Typing(step as f32 / 100.0);
            let _: Element<'_, ()> = console(&palette(), &lines(), reveal);
        }
    }

    #[test]
    fn a_typed_line_keeps_its_width() {
        // Иначе точки и значение дёргались бы на каждом знаке.
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
    fn the_graph_draws_its_own_floor() {
        // Низ графика — ось: без неё непонятно, откуда растут столбики, а
        // отсчёт «ничего не шло» толщиной в пиксел в тёмной консоли не виден.
        let element: Element<'_, ()> = axis(&palette());
        assert_eq!(element.as_widget().size().height, Length::Fixed(AXIS));
        assert_eq!(element.as_widget().size().width, Length::Fill);
    }

    #[test]
    fn the_graph_takes_all_the_height_left_over() {
        // Ради этого он и перестал быть строкой: график занимает всё, что не
        // занял текст, а не одну строку в знак высотой.
        let element: Element<'_, ()> = graph(&palette(), &[0.0, 0.5, 1.0]);
        let size = element.as_widget().size();
        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn a_bar_is_never_nothing() {
        // Столбик нулевой высоты — это квад нулевого размера, которого не
        // принимает отрисовщик, и пропавшая с графика точка.
        for share in [-1.0, 0.0, 0.001, 0.5, 1.0, 2.0] {
            let element: Element<'_, ()> = bar(palette().primary, share);
            assert_eq!(element.as_widget().size().height, Length::Fill);
        }
    }

    #[test]
    fn an_empty_graph_still_holds_its_place() {
        // Отсчётов нет — место всё равно за графиком: без этого текст расползся
        // бы по всей высоте окна.
        let element: Element<'_, ()> = graph(&palette(), &[]);
        assert_eq!(element.as_widget().size().height, Length::Fill);
    }

    #[test]
    fn a_long_value_is_clipped_not_pushed_off_the_edge() {
        // Имя профиля человек придумывает сам; на двухстах знаках оно выдавило
        // бы за край всё остальное.
        let long = "з".repeat(200);
        let clipped = clip(&long, LIMIT);
        assert_eq!(count(&clipped), LIMIT);
        assert!(clipped.ends_with(CUT), "не сказано, что значение обрезано");
    }

    #[test]
    fn cyrillic_counts_as_one_character() {
        // В байтах русская буква занимает два, и запас пробелов вышел бы вдвое
        // длиннее нужного.
        assert_eq!(count("СЕРВЕР"), 6);
        assert!("СЕРВЕР".len() > 6);
    }

    #[test]
    fn the_blinking_cursor_does_not_move_the_prompt() {
        // Место под курсор занято всегда: мигание — это знак или пробел, а не
        // знак или ничто.
        let palette = palette();
        let lit: Element<'_, ()> = prompt_line(&palette, "C:\\>", None, true);
        let dark: Element<'_, ()> = prompt_line(&palette, "C:\\>", None, false);
        assert_eq!(lit.as_widget().size(), dark.as_widget().size());
    }
}
