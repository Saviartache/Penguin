//! Запуск системных программ там, где нативного интерфейса нет.
//!
//! Вывод не разбирается как естественный язык: сообщения переводятся, коды возврата — нет.

use std::process::Command;

use crate::error::PlatformError;

/// Чем закончился запуск.
#[derive(Debug)]
pub(crate) struct Failure {
    /// Что запускали.
    program: String,
    /// Что сказала программа.
    reason: String,
    /// Код завершения; `None` — не запустилась вовсе.
    code: Option<i32>,
    /// Не хватило прав.
    denied: bool,
    /// Исполняемого файла нет (а не код 127 от оболочки).
    not_found: bool,
}

impl Failure {
    /// Не найден ли исполняемый файл.
    #[allow(dead_code, reason = "нужен не каждой системе")]
    pub(crate) fn is_not_found(&self) -> bool {
        self.not_found
    }

    /// Превращает неудачу в ошибку нужного раздела.
    pub(crate) fn into_error(self, make: fn(String) -> PlatformError, what: &str) -> PlatformError {
        if self.denied {
            return PlatformError::PermissionDenied(what.to_owned());
        }
        make(format!("{}: {}", self.program, self.reason))
    }

    /// Код возврата: по нему отказ человека отличается от сбоя.
    #[allow(dead_code, reason = "нужен не каждой системе")]
    pub(crate) fn code(&self) -> Option<i32> {
        self.code
    }

    /// Что сказала программа.
    #[allow(dead_code, reason = "нужно не каждой системе")]
    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }
}

/// Есть ли такая программа в системе.
#[allow(dead_code, reason = "нужна не каждой системе")]
pub(crate) fn exists(program: &str) -> bool {
    Command::new("/usr/bin/env")
        .args(["which", program])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Запускает программу и возвращает её вывод.
pub(crate) fn run(program: &str, arguments: &[&str]) -> Result<String, Failure> {
    finish(Command::new(program).args(arguments).output(), program)
}

/// Запускает программу, передав текст на вход (без временного файла с правилами).
#[allow(dead_code, reason = "нужна не каждой системе")]
pub(crate) fn feed(program: &str, arguments: &[&str], input: &str) -> Result<String, Failure> {
    use std::io::Write;

    let mut child = Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|err| spawn_failure(program, &err))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|err| spawn_failure(program, &err))?;
    }
    // Закрыть вход до ожидания: программа читает до конца файла.
    drop(child.stdin.take());

    finish(child.wait_with_output(), program)
}

/// Разбирает исход запуска.
fn finish(output: std::io::Result<std::process::Output>, program: &str) -> Result<String, Failure> {
    let output = output.map_err(|err| spawn_failure(program, &err))?;

    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }

    let reason = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(Failure {
        program: program.to_owned(),
        reason: if reason.is_empty() {
            format!("код возврата {}", output.status.code().unwrap_or(-1))
        } else {
            reason
        },
        code: output.status.code(),
        // Нехватку прав по коду не отличить: решает вызывающий.
        denied: false,
        not_found: false,
    })
}

/// Неудача самого запуска.
fn spawn_failure(program: &str, err: &std::io::Error) -> Failure {
    Failure {
        program: program.to_owned(),
        reason: err.to_string(),
        code: None,
        denied: err.kind() == std::io::ErrorKind::PermissionDenied,
        not_found: err.kind() == std::io::ErrorKind::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_program_is_not_found() {
        assert!(!exists("такой-программы-нет-и-не-будет"));
        assert!(exists("sh"), "оболочка есть в любой системе");
    }

    #[test]
    fn a_failing_program_reports_what_it_said() {
        let failure = run("sh", &["-c", "echo беда >&2; exit 3"]).expect_err("не удалось");
        assert!(failure.reason.contains("беда"), "{failure:?}");
    }

    #[test]
    fn a_silent_failure_reports_its_code() {
        let failure = run("sh", &["-c", "exit 7"]).expect_err("не удалось");
        assert!(failure.reason.contains('7'), "{failure:?}");
    }

    #[test]
    fn input_reaches_the_program() {
        let output = feed("cat", &[], "правила").expect("прочиталось");
        assert_eq!(output, "правила");
    }

    #[test]
    fn a_missing_program_fails_without_panicking() {
        let failure = run("такой-программы-нет-и-не-будет", &[]).expect_err("не запустилась");
        assert!(!failure.reason.is_empty());
        assert!(failure.is_not_found());
        assert_eq!(failure.code(), None);
    }

    #[test]
    fn exit_127_is_not_a_missing_executable() {
        let failure = run("sh", &["-c", "exit 127"]).expect_err("failed");
        assert_eq!(failure.code(), Some(127));
        assert!(!failure.is_not_found());
    }

    #[test]
    fn spawn_permission_denial_is_not_a_missing_executable() {
        let failure = spawn_failure("pkexec", &std::io::ErrorKind::PermissionDenied.into());
        assert!(!failure.is_not_found());
        assert_eq!(failure.code(), None);
        assert!(
            failure
                .into_error(PlatformError::Service, "elevation")
                .needs_privileges()
        );
    }
}
