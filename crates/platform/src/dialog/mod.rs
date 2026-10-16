//! Системное окно выбора файла: программа, которой нет среди запущенных, или
//! список правил для импорта; и окно сохранения списка при выгрузке.
//!
//! Вызов держит поток до ответа человека; из потока отрисовки его звать нельзя.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use std::path::PathBuf;

use crate::error::PlatformResult;

/// Что выбирают: от этого зависит отбор файлов в окне.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Program,
    RuleList,
}

/// Просит человека показать программу: `title` — заголовок окна, `filter` — подпись вида файлов
/// (обе приходят переведёнными из интерфейса). `Ok(None)` — окно закрыли без выбора.
///
/// На macOS выбирается `.app` целиком, а возвращается его исполняемый файл.
pub fn pick_program(title: &str, filter: &str) -> PlatformResult<Option<PathBuf>> {
    pick(Kind::Program, title, filter)
}

/// Просит человека показать текстовый список правил; подписи — как у [`pick_program`].
pub fn pick_rule_list(title: &str, filter: &str) -> PlatformResult<Option<PathBuf>> {
    pick(Kind::RuleList, title, filter)
}

/// Просит человека назвать файл для выгрузки списка правил; `name` — имя по умолчанию,
/// подписи — как у [`pick_program`]. `Ok(None)` — окно закрыли без выбора.
pub fn save_rule_list(title: &str, filter: &str, name: &str) -> PlatformResult<Option<PathBuf>> {
    #[cfg(windows)]
    {
        windows::save(title, filter, name)
    }
    #[cfg(target_os = "linux")]
    {
        let _ = filter;
        linux::save(title, name)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = filter;
        macos::save(title, name)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (title, filter, name);
        Err(crate::error::PlatformError::Unsupported("сохранение файла"))
    }
}

fn pick(kind: Kind, title: &str, filter: &str) -> PlatformResult<Option<PathBuf>> {
    #[cfg(windows)]
    {
        windows::pick(kind, title, filter)
    }
    #[cfg(target_os = "linux")]
    {
        let _ = kind;
        linux::pick(title, filter)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = filter;
        macos::pick(kind, title)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (kind, title, filter);
        Err(crate::error::PlatformError::Unsupported("выбор файла"))
    }
}
