//! Символьная панель: рамка, строки «поле — значение», полоска графика.
//!
//! Тем же языком, что и [`uikit::widgets::LogTerminal`]: моноширинный шрифт,
//! рамка из символов, ничего лишнего. В окне размером с ладонь это не украшение
//! — обычная карточка с подписями и отступами съела бы половину площади на
//! воздух между полями, а тут каждая строка несёт по значению.
//!
//! Рисование отделено от сборки виджета: рамка — это строка, а строку можно
//! проверить целиком, не поднимая окна.

use std::fmt::Write as _;

use iced::widget::{container, text};
use iced::{Element, Font, Length};
use uikit::style::tokens::type_scale;

/// Ширина панели в знаках.
///
/// Подобрана под узкое окно: шире — и панель начнёт растягивать окно, уже — и
/// адрес сервера перестанет помещаться целиком.
pub const WIDTH: usize = 30;

/// Символы для полоски графика, от пустоты до полной высоты.
///
/// Восемь ступеней — всё, что даёт блочный набор; больше не нарисовать, меньше
/// — и график перестанет отличать половину от четверти.
const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Одна строка панели.
pub enum Row<'a> {
    /// Поле и значение.
    Pair(&'a str, String),
    /// Полоска графика по долям от нуля до единицы.
    Chart(Vec<f32>),
    /// Пустая строка — разделитель.
    Gap,
}

/// Собирает панель.
pub fn panel<'a, Message: 'a>(title: &str, rows: &[Row<'_>]) -> Element<'a, Message> {
    container(
        text(draw(title, rows))
            .font(Font::MONOSPACE)
            .size(type_scale::BODY)
            .line_height(iced::widget::text::LineHeight::Relative(1.35)),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x()
    .center_y()
    .padding(gap())
    .style(uikit::style::container::log_terminal_viewport as fn(&iced::Theme) -> _)
    .into()
}

/// Отступ панели от края.
fn gap() -> f32 {
    uikit::layout::gap::MD
}

/// Рисует панель целиком.
///
/// Свободная функция: рамка — это текст, и проверить её можно посимвольно, не
/// поднимая окна. Съехавшая на знак рамка видна сразу, а в собранном виджете
/// её пришлось бы искать глазами на экране.
pub fn draw(title: &str, rows: &[Row<'_>]) -> String {
    let mut out = String::new();
    let inner = WIDTH - 2;

    let _ = writeln!(out, "┌{}┐", cap(title, inner));
    for row in rows {
        let _ = writeln!(out, "│{}│", body(row, inner));
    }
    let _ = write!(out, "└{}┘", "─".repeat(inner));
    out
}

/// Верхняя перекладина с названием, вписанным в неё.
fn cap(title: &str, inner: usize) -> String {
    let title = clip(title, inner.saturating_sub(4));
    let width = count(&title);
    // Название прижато влево, но не к самому углу: два знака отбивки читаются
    // как поле, а не как обрезанный текст.
    let tail = inner.saturating_sub(width + 3);
    format!("─ {title} {}", "─".repeat(tail))
}

/// Содержимое строки, дополненное до ширины панели.
fn body(row: &Row<'_>, inner: usize) -> String {
    let line = match row {
        Row::Gap => String::new(),
        Row::Chart(points) => chart(points, inner.saturating_sub(2)),
        Row::Pair(label, value) => pair(label, value, inner.saturating_sub(2)),
    };
    format!(" {} ", pad(&line, inner.saturating_sub(2)))
}

/// Поле слева, значение справа, точки между ними.
///
/// Точки, а не пробелы: в моноширинном наборе пустота между далеко разнесёнными
/// столбцами теряет связь между ними, и глаз перестаёт понимать, какое значение
/// к какому полю относится.
fn pair(label: &str, value: &str, width: usize) -> String {
    let label = clip(label, width);
    let value = clip(value, width.saturating_sub(count(&label) + 1));
    let filler = width.saturating_sub(count(&label) + count(&value));

    if filler < 2 {
        return format!("{label} {value}");
    }
    format!("{label} {} {value}", "·".repeat(filler.saturating_sub(2)))
}

/// Полоска графика на всю ширину.
fn chart(points: &[f32], width: usize) -> String {
    if points.is_empty() || width == 0 {
        return String::new();
    }

    // Берём хвост: слева уезжает старое, справа приходит новое — так же, как
    // читается любой график времени.
    let tail = points.len().saturating_sub(width);
    let mut line = String::with_capacity(width);
    for point in &points[tail..] {
        let step = (point.clamp(0.0, 1.0) * (BARS.len() - 1) as f32).round() as usize;
        line.push(BARS[step.min(BARS.len() - 1)]);
    }
    line
}

/// Дополняет строку пробелами до нужной ширины.
fn pad(line: &str, width: usize) -> String {
    let width = width.saturating_sub(count(line));
    format!("{line}{}", " ".repeat(width))
}

/// Обрезает строку по знакам, а не по байтам.
fn clip(line: &str, width: usize) -> String {
    if count(line) <= width {
        return line.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    line.chars()
        .take(width.saturating_sub(1))
        .collect::<String>()
        + "…"
}

/// Длина в знаках.
///
/// Не в байтах: русская буква занимает два, и рамка разъехалась бы на каждой
/// подписи.
fn count(line: &str) -> usize {
    line.chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(drawn: &str) -> Vec<String> {
        drawn.lines().map(str::to_owned).collect()
    }

    #[test]
    fn every_line_is_the_same_width() {
        // Съехавшая на знак рамка — первое, что видно в окне, и последнее, что
        // находится глазами в коде.
        let drawn = draw(
            "КОНФИГУРАЦИЯ",
            &[
                Row::Pair("ПРОФИЛЬ", "source".to_owned()),
                Row::Gap,
                Row::Pair("СЕРВЕР", "example.net:3478".to_owned()),
                Row::Chart(vec![0.0, 0.5, 1.0]),
            ],
        );

        for line in lines(&drawn) {
            assert_eq!(count(&line), WIDTH, "строка не той ширины: {line}");
        }
    }

    #[test]
    fn a_long_value_is_clipped_not_wrapped() {
        // Перенос сломал бы рамку; обрезка — нет.
        let drawn = draw("ЗАГОЛОВОК", &[Row::Pair("ПОЛЕ", "з".repeat(200))]);
        for line in lines(&drawn) {
            assert_eq!(count(&line), WIDTH);
        }
        assert!(drawn.contains('…'), "не сказано, что значение обрезано");
    }

    #[test]
    fn cyrillic_counts_as_one_character() {
        // В байтах русская буква занимает два, и рамка разъехалась бы на
        // каждой подписи.
        assert_eq!(count("СЕРВЕР"), 6);
        assert!("СЕРВЕР".len() > 6);
    }

    #[test]
    fn the_chart_keeps_the_newest_points() {
        // Слева уезжает старое: график времени читается только так.
        let points: Vec<f32> = (0..100).map(|step| step as f32 / 99.0).collect();
        let drawn = chart(&points, 4);
        assert_eq!(count(&drawn), 4);
        assert_eq!(
            drawn.chars().last(),
            Some('█'),
            "правый край — самый свежий"
        );
    }

    #[test]
    fn an_empty_chart_draws_nothing() {
        assert!(chart(&[], 10).is_empty());
        assert!(chart(&[0.5], 0).is_empty());
    }

    #[test]
    fn the_title_sits_inside_the_frame() {
        let drawn = draw("ТРАФИК", &[]);
        let first = drawn.lines().next().expect("строка есть");
        assert!(first.contains("ТРАФИК"));
        assert_eq!(count(first), WIDTH);
    }
}
