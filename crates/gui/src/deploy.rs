//! Развёртывание сервера Pingwin: окно просит об этом себя-как-CLI.
//!
//! По SSH ходит `penguin deploy pingwin --json` (`AGENTS.md` §1.3, §1.7): окно
//! пишет запрос в его `stdin` (пароль не попадает в аргументы) и пересказывает
//! строки `stdout`. Процесс живёт, пока жив поток: сброс задачи его убивает
//! (`kill_on_drop`).

use std::path::Path;
use std::process::Stdio;

use iced::futures::channel::mpsc::Sender;
use iced::futures::{SinkExt, Stream};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout, Command};

use crate::app::message::{DeployMessage, Message, ServersMessage};
use crate::forms::deploy::progress::parse_line;

const ARGS: [&str; 3] = ["deploy", "pingwin", "--json"];

/// Разворачивает сервер; последним приходит [`DeployMessage::Finished`].
pub(crate) fn run(request: String) -> impl Stream<Item = Message> {
    iced::stream::channel(16, async move |mut output: Sender<Message>| {
        let result = match std::env::current_exe() {
            Ok(executable) => drive(&executable, &ARGS, &request, &mut output).await,
            Err(err) => Err(err.to_string()),
        };
        // Ошибка отправки — окно уже не слушает.
        let _ = output.send(wrap(DeployMessage::Finished(result))).await;
    })
}

fn wrap(message: DeployMessage) -> Message {
    Message::Servers(ServersMessage::Deploy(message))
}

/// Запускает программу, отдаёт ей запрос и пересылает события до её выхода.
async fn drive(
    executable: &Path,
    args: &[&str],
    request: &str,
    output: &mut Sender<Message>,
) -> Result<(), String> {
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(crate::self_exec::CREATE_NO_WINDOW);

    let mut child = command.spawn().map_err(|err| err.to_string())?;
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err("каналы процесса не открылись".to_owned());
    };

    // Разом: процесс, упёршийся в полный `stderr`, иначе не дописал бы `stdout`.
    let (written, forwarded, stderr) = tokio::join!(
        write(stdin, request),
        forward(stdout, output),
        read_all(stderr)
    );
    let status = child.wait().await.map_err(|err| err.to_string())?;
    if !status.success() {
        return Err(crate::self_exec::failure(&stderr, status));
    }
    written.and(forwarded).map_err(|err| err.to_string())
}

/// Пишет запрос и закрывает `stdin`: CLI читает до конца.
async fn write(mut stdin: ChildStdin, request: &str) -> std::io::Result<()> {
    stdin.write_all(request.as_bytes()).await?;
    stdin.shutdown().await
}

async fn forward(stdout: ChildStdout, output: &mut Sender<Message>) -> std::io::Result<()> {
    let mut lines = BufReader::new(stdout).lines();
    while let Some(line) = lines.next_line().await? {
        let Some(event) = parse_line(&line) else {
            continue;
        };
        if output
            .send(wrap(DeployMessage::Event(event)))
            .await
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

/// Весь `stderr`; непрочитанный — пусто, причину тогда скажет код выхода.
async fn read_all(mut stderr: ChildStderr) -> Vec<u8> {
    let mut buffer = Vec::new();
    if stderr.read_to_end(&mut buffer).await.is_err() {
        buffer.clear();
    }
    buffer
}

#[cfg(all(test, unix))]
mod tests {
    use iced::futures::StreamExt;
    use iced::futures::channel::mpsc;

    use super::*;
    use crate::forms::deploy::Event;

    async fn script(body: &str) -> (Result<(), String>, Vec<Event>) {
        let (mut sender, receiver) = mpsc::channel(16);
        let result = drive(
            Path::new("/bin/sh"),
            &["-c", body],
            "{\"host\":\"h\"}",
            &mut sender,
        )
        .await;
        drop(sender);
        let events = receiver
            .filter_map(|message| async move {
                match message {
                    Message::Servers(ServersMessage::Deploy(DeployMessage::Event(event))) => {
                        Some(event)
                    }
                    _ => None,
                }
            })
            .collect()
            .await;
        (result, events)
    }

    #[tokio::test]
    async fn the_request_goes_to_stdin_and_events_come_back() {
        let (result, events) = script(
            r#"[ "$(cat)" = '{"host":"h"}' ] || exit 9
echo "шум"
echo '{"event":"step","id":"docker"}'
echo '{"event":"link","link":"pingwin://x"}'"#,
        )
        .await;
        assert_eq!(result, Ok(()));
        assert_eq!(
            events,
            vec![
                Event::Step("docker".to_owned()),
                Event::Link("pingwin://x".to_owned())
            ]
        );
    }

    #[tokio::test]
    async fn a_failure_reports_the_last_stderr_line() {
        let (result, events) =
            script(r#"cat >/dev/null; echo '{"event":"step","id":"cert"}'; echo "Error: DNS не тот" >&2; exit 3"#)
                .await;
        assert_eq!(result, Err("DNS не тот".to_owned()));
        assert_eq!(events, vec![Event::Step("cert".to_owned())]);
    }
}
