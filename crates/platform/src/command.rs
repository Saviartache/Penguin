//! Запуск системных программ там, где своего интерфейса у системы нет.
//!
//! Часть работы платформенного слоя делается нативно — маршруты, адаптер,
//! права ([`crate::route`], [`crate::privilege`]). Но у брандмауэра, службы и
//! настроек DNS нативного интерфейса либо нет вовсе (`launchd` и `systemd`
//! разговаривают только своими программами), либо он не задокументирован и
//! меняется от версии к версии. Там честнее вызвать системную программу, чем
//! держать копию её работы, которая однажды разойдётся с системой.
//!
//! Правило одно: **вывод не разбирается на естественном языке**. Сообщения
//! переводятся, а коды возврата — нет.

use std::process::Command;

use crate::error::PlatformError;

/// Чем закончился запуск.
#[derive(Debug)]
pub(crate) struct Failure {
    /// Что запускали.
    program: String,
    /// Что сказала программа.
    reason: String,
    /// Не хватило прав.
    denied: bool,
}

impl Failure {
    /// Превращает неудачу в ошибку нужного раздела.
    pub(crate) fn into_error(self, make: fn(String) -> PlatformError, what: &str) -> PlatformError {
        if self.denied {
            return PlatformError::PermissionDenied(what.to_owned());
        }
        make(format!("{}: {}", self.program, self.reason))
    }
}

/// Есть ли такая программа в системе.
///
/// Спрашивается заранее, чтобы сказать «поставьте `nft`», а не «команда
/// завершилась с кодом 127».
///
/// Нужна там, где нужного не оказывается в системе, — то есть на Linux;
/// у macOS все её программы на месте по построению.
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

/// Запускает программу, передав ей текст на вход.
///
/// Правила брандмауэра передаются именно так: временный файл с ними пришлось
/// бы ещё и убирать, а забытый файл с правилами — это подсказка, как их
/// подменить.
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
    // Поток закрывается до ожидания: программа читает вход до конца файла и
    // без закрытия ждала бы вечно.
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
            format!("код возврата {}", exit_code(&output.status))
        } else {
            reason
        },
        // Программа уже запустилась, значит отказ пришёл от системы, а не от
        // оболочки. Отличить нехватку прав по коду нельзя, и решает её здесь
        // вызывающий: почти всё в этом крейте прав требует.
        denied: false,
    })
}

/// Неудача самого запуска.
fn spawn_failure(program: &str, err: &std::io::Error) -> Failure {
    Failure {
        program: program.to_owned(),
        reason: err.to_string(),
        denied: err.kind() == std::io::ErrorKind::PermissionDenied,
    }
}

/// Код возврата, если он есть.
fn exit_code(status: &std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
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
        // Программа, промолчавшая в поток ошибок, всё равно должна оставить
        // след: «не сработало» без причины не лечится ничем.
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
    }
}
