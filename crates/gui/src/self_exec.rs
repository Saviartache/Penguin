//! Запуск этого же приложения как `penguin <…>` и чтение его вывода.
//!
//! В сеть к внешним сервисам (GitHub, шлюз подписки) окно само не ходит
//! (`AGENTS.md` §1.7): работу делает отдельный процесс — это же приложение в
//! роли CLI, а окно читает его `--json`.

use std::path::Path;
use std::process::Command;

/// Флаг запуска без мелькнувшей консоли у отладочной сборки.
#[cfg(windows)]
pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Запускает это же приложение с аргументами и возвращает его `stdout`.
pub(crate) fn run_self(args: &[&str]) -> Result<Vec<u8>, String> {
    let executable = std::env::current_exe().map_err(|err| err.to_string())?;
    run(&executable, args)
}

/// Запускает программу и возвращает её `stdout`; иначе — причину из `stderr`.
pub(crate) fn run(executable: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let mut command = Command::new(executable);
    command.args(args);
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut command, CREATE_NO_WINDOW);

    let output = command.output().map_err(|err| err.to_string())?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(failure(&output.stderr, output.status))
    }
}

/// Причина отказа: последняя непустая строка `stderr` без «Error: ».
pub(crate) fn failure(stderr: &[u8], status: std::process::ExitStatus) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty());
    match line {
        Some(line) => line.strip_prefix("Error: ").unwrap_or(line).to_owned(),
        None => status.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn the_last_stderr_line_is_the_reason() {
        use std::os::unix::process::ExitStatusExt;

        let status = std::process::ExitStatus::from_raw(256);
        assert_eq!(
            failure("Error: SHA-256 не сошёлся\n\n".as_bytes(), status),
            "SHA-256 не сошёлся"
        );
        assert!(!failure(b"", status).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_child_that_fails_is_an_error_and_one_that_prints_is_read() {
        let ok = run(Path::new("/bin/echo"), &["{}"]).expect("echo");
        assert_eq!(ok, b"{}\n");
        assert!(run(Path::new("/usr/bin/false"), &[]).is_err());
    }
}
