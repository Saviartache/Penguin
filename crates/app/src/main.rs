//! Penguin: один исполняемый файл на три роли — окно, терминал, служба.
//!
//! Тоннелю нужны права системы, окну они вредны, поэтому процессов три; кем быть
//! в этот раз, файл решает по аргументам ([`args`]) и права просит только когда
//! они нужны ([`penguin_platform::run_elevated`]). Файл собран как оконный, а к
//! консоли родителя подключается [`console`].

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// В исполняемом крейте `pub` лишь открывает элемент соседним модулям.
#![allow(unreachable_pub)]

mod args;
mod console;
mod help;
mod logging;
mod service;
mod single;

use std::io::Write;

use anyhow::{Context, Result};
use args::{Cli, Command, ServiceCommand};
use penguin_cli::args::Parsed;

fn main() -> Result<()> {
    // `ssh` зовёт нас как SSH_ASKPASS с подсказкой в аргументе — до разбора аргументов.
    if let Some(password) = penguin_cli::askpass::reply() {
        std::io::stdout().write_all(password.as_bytes())?;
        return Ok(());
    }
    let mut cli = match args::from_env() {
        Ok(Parsed::Run(cli)) => cli,
        Ok(Parsed::Print(text)) => {
            console::attach_to_parent();
            let _ = std::io::stdout().write_all(text.as_bytes());
            return Ok(());
        }
        Err(err) => {
            console::attach_to_parent();
            eprintln!("ошибка: {err}\n\nПодробнее: penguin --help");
            std::process::exit(2);
        }
    };

    // До первой печати.
    if cli.writes_to_console() {
        console::attach_to_parent();
    }
    prepare_arguments(&mut cli)?;

    // Права спрашиваются один раз и заранее, а не на середине команды.
    if cli.needs_elevation() && !penguin_platform::is_elevated() {
        return elevate_and_exit(&cli);
    }

    logging::init(&cli);

    match &cli.command {
        Some(Command::Service(command)) => {
            service::run(command, cli.controller_uid, cli.import_config.as_deref())
        }
        Some(Command::Client(command)) => {
            penguin_cli::run(command, cli.config_dir.as_deref(), cli.json)
        }
        None if cli.service => penguin_daemon::service::run_as_service(cli.config_dir),
        None if cli.foreground => {
            penguin_daemon::runtime::run_foreground(cli.config_dir, cli.verbose)
        }
        None => {
            // Второе окно тихо уступает первому.
            let Some(_single) = single::lock_window()? else {
                return Ok(());
            };
            penguin_gui::run(cli.tray).context("окно не открылось")
        }
    }
}

/// Запоминает пользовательские значения до того, как pkexec/osascript сменят окружение.
fn prepare_arguments(cli: &mut Cli) -> Result<()> {
    let Some(Command::Service(command)) = &cli.command else {
        anyhow::ensure!(
            cli.controller_uid.is_none() && cli.import_config.is_none(),
            "controller/import options require a service command"
        );
        return Ok(());
    };
    anyhow::ensure!(
        cli.config_dir.is_none(),
        "service commands use the machine configuration directory; --config-dir is only supported by --foreground, --service and client commands"
    );
    if !service::prepares_service(command) {
        anyhow::ensure!(
            cli.controller_uid.is_none() && cli.import_config.is_none(),
            "controller/import options require service ensure, install, start or restart"
        );
        return Ok(());
    }
    if !penguin_platform::is_elevated() {
        // HOME повышенной учётной записи источником импорта быть не может.
        cli.controller_uid = penguin_daemon::current_user_id();
        if cli.import_config.is_none() {
            cli.import_config = penguin_config::Paths::user()
                .ok()
                .map(|paths| paths.config_file())
                .filter(|path| path.is_file());
        }
    }
    if let Some(path) = &cli.import_config {
        cli.import_config = Some(std::path::absolute(path).context("invalid import path")?);
    }
    Ok(())
}

/// Перезапускает себя с правами и завершает текущий процесс.
fn elevate_and_exit(cli: &Cli) -> Result<()> {
    let arguments = elevated_arguments(cli);
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();

    if penguin_platform::run_elevated(&borrowed)? {
        return Ok(());
    }
    // Отказ в окне UAC — решение человека, а не сбой.
    anyhow::bail!("нужны права администратора");
}

/// Аргументы для перезапуска; потерянный `--config-dir` — служба не для того каталога.
fn elevated_arguments(cli: &Cli) -> Vec<String> {
    let name = match cli.command {
        Some(Command::Service(ServiceCommand::Ensure)) => "ensure",
        Some(Command::Service(ServiceCommand::Install)) => "install",
        Some(Command::Service(ServiceCommand::Uninstall)) => "uninstall",
        Some(Command::Service(ServiceCommand::Restart)) => "restart",
        Some(Command::Service(ServiceCommand::Start)) => "start",
        Some(Command::Service(ServiceCommand::Stop)) => "stop",
        // Остальные команды отсеяны в `needs_elevation`.
        _ => "status",
    };
    let mut arguments = vec!["service".to_owned(), name.to_owned()];

    if let Some(dir) = &cli.config_dir {
        // Кавычки пути ставит платформа, передающая аргументы одной строкой.
        arguments.extend(["--config-dir".to_owned(), dir.display().to_string()]);
    }
    if cli.verbose {
        arguments.push("--verbose".to_owned());
    }
    if let Some(uid) = cli.controller_uid {
        arguments.extend(["--controller-uid".to_owned(), uid.to_string()]);
    }
    if let Some(path) = &cli.import_config {
        arguments.extend(["--import-config".to_owned(), path.display().to_string()]);
    }
    arguments
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[String]) -> Cli {
        match args::parse(args.to_vec()) {
            Ok(Parsed::Run(cli)) => cli,
            other => panic!("не запуск: {other:?}"),
        }
    }

    fn cli(args: &[&str]) -> Cli {
        parse(
            &args
                .iter()
                .skip(1)
                .map(|arg| (*arg).to_owned())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn elevated_arguments_keep_the_command() {
        assert_eq!(
            elevated_arguments(&cli(&["penguin", "service", "ensure"])),
            ["service", "ensure"]
        );
        assert_eq!(
            elevated_arguments(&cli(&["penguin", "service", "install"])),
            ["service", "install"]
        );
    }

    #[test]
    fn elevated_arguments_keep_the_config_directory() {
        let arguments = elevated_arguments(&cli(&[
            "penguin",
            "service",
            "ensure",
            "--config-dir",
            "C:/penguin",
        ]));

        assert!(arguments.iter().any(|argument| argument == "--config-dir"));
        assert!(
            arguments
                .iter()
                .any(|argument| argument.contains("penguin"))
        );
    }

    #[test]
    fn a_path_with_spaces_stays_one_argument() {
        // Кавычки поставит платформа; здесь они стали бы частью имени.
        let arguments = elevated_arguments(&cli(&[
            "penguin",
            "service",
            "ensure",
            "--config-dir",
            "C:/Program Files/Penguin",
        ]));

        let path = arguments.last().expect("путь есть");
        assert_eq!(path, "C:/Program Files/Penguin");
    }

    #[test]
    fn verbose_survives_the_elevation() {
        let arguments = elevated_arguments(&cli(&["penguin", "service", "ensure", "--verbose"]));
        assert!(arguments.iter().any(|argument| argument == "--verbose"));
    }

    #[test]
    fn desktop_identity_and_import_source_survive_elevation() {
        let original = cli(&[
            "penguin",
            "service",
            "ensure",
            "--controller-uid",
            "501",
            "--import-config",
            "/Users/alice/My Settings/config.toml",
        ]);
        let reparsed = parse(&elevated_arguments(&original));
        assert_eq!(reparsed.controller_uid, Some(501));
        assert_eq!(reparsed.import_config, original.import_config);
    }

    #[test]
    fn service_commands_do_not_silently_ignore_custom_config() {
        let mut cli = cli(&["penguin", "service", "ensure", "--config-dir", "custom"]);
        assert!(prepare_arguments(&mut cli).is_err());
    }

    #[test]
    fn read_only_commands_cannot_grant_control() {
        let mut cli = cli(&["penguin", "service", "status", "--controller-uid", "501"]);
        assert!(prepare_arguments(&mut cli).is_err());
    }
}
