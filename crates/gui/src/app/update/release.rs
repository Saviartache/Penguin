//! Обновление программы.
//!
//! В сеть окно не ходит: проверку и установку делает отдельный процесс — это же приложение,
//! запущенное как `penguin update check|install`. Окно читает его вывод и перезапускается.

use std::path::{Path, PathBuf};
use std::process::Command;

use iced::Task;
use penguin_ipc::schema::LogLevel;
use penguin_update::{CheckReport, schedule};

use crate::app::App;
use crate::app::message::{Message, UpdateMessage, WindowMessage};
use crate::app::state::UpdateStatus;
use crate::app::update::connection::shutdown_service;

/// Файл с временем последней проверки.
const STAMP: &str = "update-check";

/// Разбирает сообщения обновления.
pub fn handle(app: &mut App, message: UpdateMessage) -> Task<Message> {
    match message {
        UpdateMessage::Check => begin_check(app, true),
        UpdateMessage::Checked { manual, result } => checked(app, manual, result),
        UpdateMessage::Install => install(app),
        UpdateMessage::Installed(result) => installed(app, result),
    }
}

/// Проверка при запуске: раз за сеанс, если включена и пора.
pub fn startup_check(app: &mut App) -> Task<Message> {
    let state = app.state_mut();
    if std::mem::replace(&mut state.updates.startup_done, true) {
        return Task::none();
    }
    if !state.config.app.check_updates || !due() {
        return Task::none();
    }
    begin_check(app, false)
}

fn begin_check(app: &mut App, manual: bool) -> Task<Message> {
    let updates = &mut app.state_mut().updates;
    if matches!(
        updates.status,
        UpdateStatus::Checking | UpdateStatus::Installing | UpdateStatus::Restarting
    ) {
        return Task::none();
    }
    updates.status = UpdateStatus::Checking;
    Task::perform(check(), move |result| {
        Message::Update(UpdateMessage::Checked { manual, result })
    })
}

fn checked(app: &mut App, manual: bool, result: Result<CheckReport, String>) -> Task<Message> {
    let state = app.state_mut();
    match result {
        Ok(CheckReport {
            available: Some(found),
            ..
        }) => {
            if !manual {
                let strings = crate::i18n::s();
                state.connection.push_log(
                    LogLevel::Info,
                    format!("{}: {}", strings.update_available, found.version),
                );
            }
            state.updates.status = UpdateStatus::Available(found);
        }
        Ok(_) => state.updates.status = UpdateStatus::Latest,
        // Тихая проверка при запуске не должна пугать: нет сети — не новость.
        Err(reason) if !manual => {
            tracing::warn!(%reason, "обновления не проверены");
            state.updates.status = UpdateStatus::Idle;
        }
        Err(reason) => state.updates.status = UpdateStatus::Failed(reason),
    }
    Task::none()
}

fn install(app: &mut App) -> Task<Message> {
    let updates = &mut app.state_mut().updates;
    if !matches!(updates.status, UpdateStatus::Available(_)) {
        return Task::none();
    }
    updates.status = UpdateStatus::Installing;
    Task::perform(run_install(), |result| {
        Message::Update(UpdateMessage::Installed(result))
    })
}

fn installed(app: &mut App, result: Result<PathBuf, String>) -> Task<Message> {
    let online = app.state().connection.online;
    let updates = &mut app.state_mut().updates;
    match result {
        Ok(executable) => {
            updates.status = UpdateStatus::Restarting;
            Task::perform(restart(online, executable), |()| {
                Message::Window(WindowMessage::Stopped)
            })
        }
        Err(reason) => {
            updates.status = UpdateStatus::Failed(reason);
            Task::none()
        }
    }
}

/// Файл с отметкой проверки: в профиле пользователя, окну туда писать можно.
fn stamp_file() -> Option<PathBuf> {
    penguin_config::Paths::user()
        .ok()
        .map(|paths| paths.data_dir().join(STAMP))
}

fn due() -> bool {
    let last = stamp_file().and_then(|file| schedule::last_check(&file));
    schedule::is_due(last, schedule::now_secs())
}

async fn check() -> Result<CheckReport, String> {
    tokio::task::spawn_blocking(|| {
        let output = run_self(&["update", "check", "--json"])?;
        let report = parse_report(&output)?;
        if let Some(file) = stamp_file()
            && let Err(err) = schedule::mark_checked(&file, schedule::now_secs())
        {
            tracing::warn!(%err, "время проверки не записано");
        }
        Ok(report)
    })
    .await
    .map_err(|err| err.to_string())?
}

async fn run_install() -> Result<PathBuf, String> {
    tokio::task::spawn_blocking(|| {
        // До подмены: на Linux после неё путь работающего файла заканчивается на «(deleted)».
        let executable = std::env::current_exe().map_err(|err| err.to_string())?;
        run_self(&["update", "install"])?;
        Ok(executable)
    })
    .await
    .map_err(|err| err.to_string())?
}

/// Опускает службу, запускает новую сборку и отдаёт окну команду закрыться.
async fn restart(online: bool, executable: PathBuf) {
    if online {
        shutdown_service().await;
    }
    match tokio::task::spawn_blocking(move || Command::new(executable).spawn()).await {
        Ok(Ok(_child)) => {}
        Ok(Err(err)) => tracing::error!(%err, "новая сборка не запустилась"),
        Err(err) => tracing::error!(%err, "новая сборка не запустилась"),
    }
}

/// Запускает это же приложение с аргументами и возвращает его вывод.
fn run_self(args: &[&str]) -> Result<Vec<u8>, String> {
    let executable = std::env::current_exe().map_err(|err| err.to_string())?;
    run(&executable, args)
}

fn run(executable: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let mut command = Command::new(executable);
    command.args(args);
    #[cfg(windows)]
    {
        // Без мелькнувшей консоли у отладочной сборки.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        std::os::windows::process::CommandExt::creation_flags(&mut command, CREATE_NO_WINDOW);
    }

    let output = command.output().map_err(|err| err.to_string())?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(failure(&output.stderr, output.status))
    }
}

/// Причина отказа: последняя непустая строка stderr без «Error: ».
fn failure(stderr: &[u8], status: std::process::ExitStatus) -> String {
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

fn parse_report(stdout: &[u8]) -> Result<CheckReport, String> {
    serde_json::from_slice(stdout).map_err(|err| format!("ответ проверки не разобрался: {err}"))
}

#[cfg(test)]
mod tests {
    use penguin_update::Available;

    use super::*;

    fn app() -> App {
        let (app, _task) = App::new(uikit::ThemeType::Dark, false);
        app
    }

    fn found() -> Available {
        Available {
            version: "0.8.0".into(),
            page_url: "https://github.com/Saviartache/penguin/releases/tag/v0.8.0".into(),
            archive_name: "a".into(),
            archive_url: "b".into(),
            sums_url: "c".into(),
        }
    }

    fn report(available: Option<Available>) -> CheckReport {
        CheckReport {
            current: "0.7.2".into(),
            available,
        }
    }

    #[test]
    fn a_found_release_is_offered_and_announced_once_at_startup() {
        let mut app = app();
        let before = app.state().connection.log.len();

        let _ = checked(&mut app, false, Ok(report(Some(found()))));

        assert_eq!(app.state().updates.status, UpdateStatus::Available(found()));
        assert_eq!(app.state().connection.log.len(), before + 1);
    }

    #[test]
    fn a_manual_check_does_not_write_to_the_journal() {
        let mut app = app();
        let before = app.state().connection.log.len();

        let _ = checked(&mut app, true, Ok(report(Some(found()))));

        assert_eq!(app.state().connection.log.len(), before);
    }

    #[test]
    fn no_news_is_reported_as_latest() {
        let mut app = app();
        let _ = checked(&mut app, true, Ok(report(None)));
        assert_eq!(app.state().updates.status, UpdateStatus::Latest);
    }

    #[test]
    fn a_failed_startup_check_stays_quiet_but_a_manual_one_says_why() {
        let mut app = app();

        let _ = checked(&mut app, false, Err("нет сети".into()));
        assert_eq!(app.state().updates.status, UpdateStatus::Idle);

        let _ = checked(&mut app, true, Err("нет сети".into()));
        assert_eq!(
            app.state().updates.status,
            UpdateStatus::Failed("нет сети".into())
        );
    }

    #[test]
    fn startup_decides_once_and_respects_the_setting() {
        let mut app = app();
        app.state_mut().config.app.check_updates = false;

        let _ = startup_check(&mut app);
        assert!(app.state().updates.startup_done);
        assert_eq!(app.state().updates.status, UpdateStatus::Idle);

        // Второй вызов — после включения — ничего не меняет: решено на сеанс.
        app.state_mut().config.app.check_updates = true;
        let _ = startup_check(&mut app);
        assert_eq!(app.state().updates.status, UpdateStatus::Idle);
    }

    #[test]
    fn install_needs_an_offered_release() {
        let mut app = app();
        let _ = install(&mut app);
        assert_eq!(app.state().updates.status, UpdateStatus::Idle);

        app.state_mut().updates.status = UpdateStatus::Available(found());
        let _ = install(&mut app);
        assert_eq!(app.state().updates.status, UpdateStatus::Installing);
    }

    #[test]
    fn a_busy_check_is_not_started_twice() {
        let mut app = app();
        app.state_mut().updates.status = UpdateStatus::Installing;
        let _ = begin_check(&mut app, true);
        assert_eq!(app.state().updates.status, UpdateStatus::Installing);
    }

    #[test]
    fn a_failed_install_keeps_the_window_open_with_the_reason() {
        let mut app = app();
        let _ = installed(&mut app, Err("SHA-256 не сошёлся".into()));
        assert_eq!(
            app.state().updates.status,
            UpdateStatus::Failed("SHA-256 не сошёлся".into())
        );
    }

    #[test]
    fn the_report_the_cli_prints_is_understood() {
        let json = serde_json::to_vec(&report(Some(found()))).expect("json");
        assert_eq!(parse_report(&json).expect("разбор"), report(Some(found())));
        assert!(parse_report(b"not json").is_err());
    }

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
