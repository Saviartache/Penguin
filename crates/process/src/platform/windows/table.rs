//! Общее чтение таблиц переменной длины из `IP Helper`.
//!
//! `GetExtendedTcpTable` и `GetExtendedUdpTable` устроены одинаково: сначала
//! их зовут с нулевым буфером, чтобы узнать нужный размер, потом — с буфером
//! этого размера. Между двумя вызовами таблица может подрасти, поэтому попытка
//! повторяется, а не считается ошибкой.

#![allow(unsafe_code, reason = "чтение системной таблицы переменной длины")]

use std::net::SocketAddr;

use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR, WIN32_ERROR};

/// Одна запись таблицы: чей локальный адрес.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Локальный адрес соединения.
    pub local: SocketAddr,
    /// Процесс-владелец.
    pub pid: u32,
}

/// Сколько раз пробовать, если таблица растёт между вызовами.
const ATTEMPTS: usize = 4;

/// Запас к запрошенному размеру.
///
/// Между двумя вызовами появляются новые соединения, и точный размер из
/// первого вызова оказывается мал уже во втором. Запас делает такое редким.
const HEADROOM: u32 = 4096;

/// Зовёт системную функцию, подбирая размер буфера.
///
/// `call` получает указатель на буфер и изменяемый размер, а возвращает код
/// ошибки Windows — ровно как это делают функции `IP Helper`.
pub fn query_table<F>(mut call: F) -> Option<Vec<u8>>
where
    F: FnMut(*mut core::ffi::c_void, *mut u32) -> WIN32_ERROR,
{
    let mut size: u32 = 0;

    for _ in 0..ATTEMPTS {
        // Первый заход с нулевым буфером: система сообщает нужный размер.
        let probe = call(std::ptr::null_mut(), &mut size);
        if probe != ERROR_INSUFFICIENT_BUFFER && probe != NO_ERROR {
            tracing::debug!(code = probe.0, "не удалось узнать размер таблицы");
            return None;
        }
        if size == 0 {
            return None;
        }

        size = size.saturating_add(HEADROOM);
        let mut buffer = vec![0u8; size as usize];

        let result = call(buffer.as_mut_ptr().cast(), &mut size);
        match result {
            NO_ERROR => return Some(buffer),
            // Таблица подросла между вызовами — пробуем ещё раз с новым
            // размером, который система уже записала в `size`.
            ERROR_INSUFFICIENT_BUFFER => continue,
            other => {
                tracing::debug!(code = other.0, "не удалось прочитать таблицу");
                return None;
            }
        }
    }

    tracing::debug!("таблица соединений растёт быстрее, чем читается");
    None
}

/// Срез записей, лежащих сразу за заголовком таблицы.
///
/// # Safety
///
/// Заголовок по-английски: по нему clippy и проверяет, что у `unsafe`-функции
/// раздел о безопасности вообще есть.
///
/// Вызывающий обязан гарантировать, что `table` указывает на буфер,
/// заполненный системой, а `count` — то самое число записей, которое система
/// в нём объявила.
pub unsafe fn rows_of<'a, Table, Row>(table: *const Table, count: usize) -> &'a [Row] {
    // Записи начинаются сразу за заголовком. Смещение считается от поля
    // `table` самой структуры, а не от её конца: у структуры может быть
    // выравнивание, и `size_of::<Table>()` тут соврал бы.
    //
    // В объявлениях Windows поле-массив описано как `[Row; 1]`, то есть лежит
    // ровно в `size_of::<Table>() - size_of::<Row>()` от начала.
    let offset = std::mem::size_of::<Table>() - std::mem::size_of::<Row>();
    let first = unsafe { table.cast::<u8>().add(offset).cast::<Row>() };
    unsafe { std::slice::from_raw_parts(first, count) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gives_up_instead_of_looping_forever() {
        // Функция, всегда требующая больше места, не должна вешать клиент.
        let mut calls = 0;
        let result = query_table(|buf, size| {
            calls += 1;
            unsafe { *size = 1024 };
            // Места мало **всегда**, сколько ни дай: ровно тот случай, в
            // котором наивный цикл «спроси размер — выдели — повтори» не
            // заканчивается никогда.
            let _ = buf;
            ERROR_INSUFFICIENT_BUFFER
        });
        assert!(result.is_none());
        assert!(calls <= ATTEMPTS * 2, "слишком много попыток: {calls}");
    }

    #[test]
    fn empty_table_is_not_an_error_state() {
        let result = query_table(|_buf, size| {
            unsafe { *size = 0 };
            NO_ERROR
        });
        assert!(result.is_none());
    }

    #[test]
    fn succeeds_on_the_second_call() {
        let mut calls = 0;
        let result = query_table(|buf, size| {
            calls += 1;
            if buf.is_null() {
                unsafe { *size = 128 };
                ERROR_INSUFFICIENT_BUFFER
            } else {
                NO_ERROR
            }
        });
        let buffer = result.expect("буфер получен");
        assert_eq!(buffer.len(), (128 + HEADROOM) as usize);
        assert_eq!(calls, 2);
    }
}
