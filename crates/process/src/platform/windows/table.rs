//! Чтение таблиц переменной длины из `IP Helper`: размер → буфер → повтор, если таблица выросла.

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

/// Запас к размеру: между вызовами появляются новые соединения.
const HEADROOM: u32 = 4096;

/// Зовёт системную функцию (буфер, размер → код ошибки), подбирая размер буфера.
pub fn query_table<F>(mut call: F) -> Option<Vec<u8>>
where
    F: FnMut(*mut core::ffi::c_void, *mut u32) -> WIN32_ERROR,
{
    let mut size: u32 = 0;

    for _ in 0..ATTEMPTS {
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

/// Срез записей сразу за заголовком таблицы (поле-массив `[Row; 1]` лежит в конце структуры).
///
/// # Safety
///
/// `table` указывает на буфер, заполненный системой, а `count` — число записей, объявленное в нём.
pub unsafe fn rows_of<'a, Table, Row>(table: *const Table, count: usize) -> &'a [Row] {
    let offset = std::mem::size_of::<Table>() - std::mem::size_of::<Row>();
    let first = unsafe { table.cast::<u8>().add(offset).cast::<Row>() };
    unsafe { std::slice::from_raw_parts(first, count) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gives_up_instead_of_looping_forever() {
        let mut calls = 0;
        let result = query_table(|buf, size| {
            calls += 1;
            unsafe { *size = 1024 };
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
