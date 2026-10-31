//! Запуск `ssh` со сценарием на stdin и чтение его хода.

use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::thread;

use anyhow::{Context, Result, anyhow, bail};

use super::event::{Event, parse_line};
use super::request::Request;
use super::ssh;
use crate::output::{self, Format};

/// Сценарий установки на сервере.
const SCRIPT: &str = include_str!("../../../../../servers/pingwin/docker/install.sh");

/// Сколько последних строк `stderr` хранить для причины отказа.
const TAIL: usize = 5;

/// Ставит сервер Pingwin по запросу из stdin.
pub fn run(format: Format) -> Result<()> {
    let request: Request = serde_json::from_reader(io::stdin().lock())
        .map_err(|err| anyhow!("запрос не разобран: {err}"))?;
    request.validate()?;
    let askpass = std::env::current_exe().context("путь к себе неизвестен")?;
    let call = ssh::invocation(&request, &askpass, &ssh::source_url());

    let mut child = match Command::new("ssh")
        .args(&call.args)
        .envs(call.env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            bail!("ssh не найден — установите OpenSSH")
        }
        Err(err) => bail!("ssh не запустился: {err}"),
    };
    let (Some(mut stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        bail!("ssh запущен без каналов");
    };

    // Отдельно: ssh может не дочитать сценарий, пока мы не читаем его вывод.
    let feeder = thread::spawn(move || stdin.write_all(SCRIPT.as_bytes()));
    let errors = thread::spawn(move || tail(stderr));

    let mut link = None;
    let mut failure = None;
    for line in lines(stdout) {
        match parse_line(&line?) {
            Some(Event::Fail { text }) => failure = Some(text),
            Some(event) => {
                if let Event::Link { link: value } = &event {
                    link = Some(value.clone());
                }
                show(format, &event)?;
            }
            None => {}
        }
    }

    let status = child.wait().context("ssh не завершился")?;
    let stderr_tail = errors
        .join()
        .map_err(|_| anyhow!("чтение stderr ssh упало"))?;
    let fed = feeder
        .join()
        .map_err(|_| anyhow!("передача сценария упала"))?;

    if let Some(text) = failure {
        bail!(text);
    }
    if !status.success() {
        if stderr_tail.is_empty() {
            bail!("ssh завершился с ошибкой ({status})");
        }
        // Одной строкой: окно берёт причину из последней строки stderr.
        bail!(stderr_tail.join("; "));
    }
    fed.context("сценарий не передан на сервер")?;
    let link = link.context("сервер не прислал ссылку")?;
    if format == Format::Text {
        println!("\n{link}");
    }
    Ok(())
}

fn show(format: Format, event: &Event) -> Result<()> {
    match format {
        // `println!` в канал сбрасывается построчно: окно видит ход сразу.
        Format::Json => println!("{}", serde_json::to_string(event)?),
        Format::Text => match event {
            Event::Step { id } => println!("— {id}"),
            Event::Ok { text } => println!("  {}", output::ok(text)),
            Event::Info { text } => println!("  {text}"),
            Event::Link { .. } | Event::Fail { .. } => {}
        },
    }
    io::stdout().flush().context("stdout закрыт")
}

/// Строки без требования UTF-8: шум сборки бывает любым.
fn lines(source: impl Read) -> impl Iterator<Item = io::Result<String>> {
    let mut reader = BufReader::new(source);
    std::iter::from_fn(move || {
        let mut buffer = Vec::new();
        match reader.read_until(b'\n', &mut buffer) {
            Ok(0) => None,
            Ok(_) => Some(Ok(String::from_utf8_lossy(&buffer).into_owned())),
            Err(err) => Some(Err(err)),
        }
    })
}

/// Последние непустые строки `stderr`.
fn tail(source: impl Read) -> Vec<String> {
    let mut kept = VecDeque::with_capacity(TAIL);
    for line in lines(source).map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if kept.len() == TAIL {
            kept.pop_front();
        }
        kept.push_back(line.to_owned());
    }
    kept.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_keeps_the_last_lines() {
        let text = "a\n\nb\nc\nd\ne\nf\nPermission denied (publickey,password).\r\n";
        assert_eq!(
            tail(text.as_bytes()),
            [
                "c",
                "d",
                "e",
                "f",
                "Permission denied (publickey,password)."
            ]
        );
    }

    #[test]
    fn lines_survive_broken_utf8() {
        let read: Vec<String> = lines(&b"::ok \xff\n::step x"[..])
            .map(|line| line.expect("строка"))
            .collect();
        assert_eq!(read.len(), 2);
        assert_eq!(parse_line(&read[1]), Some(Event::Step { id: "x".into() }));
    }
}
