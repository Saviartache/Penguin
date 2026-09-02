//! Перечисление процессов и извлечение иконки.
//!
//! Иконка нужна одному экрану — выбору приложений — и ничему больше, поэтому
//! она за фичей `icon`: без неё крейт не тянет ни графических зависимостей,
//! ни разбора PE-ресурсов.

#![allow(unsafe_code, reason = "системные вызовы Windows")]

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

use super::path;
use crate::enumerate::ProcessEnumerator;
use crate::identity::ProcessIdentity;

/// Перечисление процессов в Windows.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsEnumerator;

impl ProcessEnumerator for WindowsEnumerator {
    fn list(&self) -> Vec<ProcessIdentity> {
        let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
            tracing::debug!("не удалось снять список процессов");
            return Vec::new();
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut identities = Vec::new();

        if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
            loop {
                // Путь берётся отдельным вызовом, а не из `szExeFile`: там
                // лежит только имя файла, а правила пишутся на путь.
                // Процессы, до которых нет доступа, просто пропускаются —
                // системных среди них большинство, и падать из-за них незачем.
                if let Some(identity) = path::identity_of(entry.th32ProcessID) {
                    identities.push(identity);
                }

                if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                    break;
                }
            }
        }

        let _ = unsafe { CloseHandle(snapshot) };
        identities
    }
}

/// Иконка исполняемого файла в виде PNG.
///
/// Заглушка: извлечение иконок из ресурсов PE — отдельная работа, и
/// откладывать из-за неё список приложений незачем. Интерфейс рисует
/// заглушку, когда иконки нет.
#[cfg(feature = "icon")]
pub fn icon_of(_path: &str) -> Option<Vec<u8>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_running_processes() {
        let processes = WindowsEnumerator.list();
        assert!(!processes.is_empty(), "не найдено ни одного процесса");
    }

    #[test]
    fn finds_ourselves_in_the_list() {
        let ours = std::process::id();
        let found = WindowsEnumerator.list().into_iter().any(|p| p.pid == ours);
        assert!(found, "собственный процесс не найден в списке");
    }

    #[test]
    fn apps_are_collapsed_and_sorted() {
        let apps = WindowsEnumerator.list_apps();
        assert!(!apps.is_empty());

        // Свёртка по пути обязана убрать повторы: у системы всегда есть
        // несколько процессов с одним и тем же исполняемым файлом.
        let mut paths: Vec<&str> = apps.iter().map(|a| &*a.identity.path).collect();
        let before = paths.len();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), before, "в списке остались повторы путей");
    }
}
