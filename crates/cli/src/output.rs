//! Вывод: человекочитаемый и JSON.
//!
//! Два вида вывода нужны разным читателям. Человек смотрит на таблицу; скрипт
//! разбирает JSON, и любое изменение оформления таблицы его бы сломало.
//! Поэтому команды не печатают строки сами, а отдают данные сюда.

use serde::Serialize;

/// Как печатать.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Для человека.
    Text,
    /// Для скрипта.
    Json,
}

impl Format {
    /// Формат по флагу `--json`.
    pub fn from_flag(json: bool) -> Self {
        if json { Self::Json } else { Self::Text }
    }
}

/// Печатает значение в выбранном формате.
///
/// В текстовом виде вызывается `render`, в машинном — сериализация. Оба
/// представления строятся из одних и тех же данных, поэтому разойтись не
/// могут.
pub fn emit<T, F>(format: Format, value: &T, render: F)
where
    T: Serialize,
    F: FnOnce(&T) -> String,
{
    match format {
        Format::Text => println!("{}", render(value)),
        Format::Json => match serde_json::to_string_pretty(value) {
            Ok(json) => println!("{json}"),
            // Сериализация своих же типов не ломается, но паниковать в выводе
            // всё равно не за что.
            Err(err) => eprintln!("не удалось собрать JSON: {err}"),
        },
    }
}

/// Собирает таблицу с выровненными колонками.
///
/// Ширина считается по самой длинной ячейке, а не задаётся числом: имена
/// профилей и правил бывают любой длины, а съехавшая таблица нечитаема.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let columns = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();

    for row in rows {
        for (index, cell) in row.iter().take(columns).enumerate() {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }

    let mut out = String::new();
    for (index, header) in headers.iter().enumerate() {
        pad(&mut out, header, widths[index], index + 1 == columns);
    }
    out.push('\n');

    for (index, width) in widths.iter().enumerate() {
        out.push_str(&"─".repeat(*width));
        if index + 1 != columns {
            out.push_str("  ");
        }
    }

    for row in rows {
        out.push('\n');
        for (index, cell) in row.iter().take(columns).enumerate() {
            pad(&mut out, cell, widths[index], index + 1 == columns);
        }
    }
    out
}

fn pad(out: &mut String, cell: &str, width: usize, last: bool) {
    out.push_str(cell);
    if !last {
        // Считаем символы, а не байты: кириллица занимает по два байта, и
        // выравнивание по длине в байтах разъехалось бы.
        let padding = width.saturating_sub(cell.chars().count());
        out.push_str(&" ".repeat(padding));
        out.push_str("  ");
    }
}

/// Строка успеха.
pub fn ok(message: impl std::fmt::Display) -> String {
    format!("✓ {message}")
}

/// Строка отказа.
pub fn fail(message: impl std::fmt::Display) -> String {
    format!("✗ {message}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_aligns_columns() {
        let rendered = table(
            &["имя", "адрес"],
            &[
                vec!["дом".to_owned(), "example.com:443".to_owned()],
                vec!["очень длинное имя".to_owned(), "a:1".to_owned()],
            ],
        );

        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 4, "заголовок, разделитель и две строки");
        // Колонка расширилась под самое длинное имя.
        assert!(lines[0].starts_with("имя                "));
    }

    #[test]
    fn table_counts_characters_not_bytes() {
        // Кириллица занимает по два байта; выравнивание по байтам разъехалось
        // бы на каждой русской строке.
        let rendered = table(&["a"], &[vec!["ЯЯЯ".to_owned()]]);
        let separator = rendered.lines().nth(1).expect("разделитель");
        assert_eq!(separator.chars().count(), 3);
    }

    #[test]
    fn table_survives_ragged_rows() {
        let rendered = table(&["a", "b"], &[vec!["1".to_owned()]]);
        assert!(rendered.contains('1'));
    }

    #[test]
    fn format_follows_the_flag() {
        assert_eq!(Format::from_flag(true), Format::Json);
        assert_eq!(Format::from_flag(false), Format::Text);
    }
}
