//! Penguin: один исполняемый файл на три роли.
//!
//! # Почему ролей три, а файл один
//!
//! Тоннелю нужны права системы: TUN-адаптер, таблица маршрутизации и
//! брандмауэр без них недоступны. Окну права не нужны и **вредны** — вместе с
//! ним под системной учётной записью работал бы весь `iced`, `wgpu` и драйвер
//! видеокарты. Поэтому внутри программа остаётся тремя процессами.
//!
//! Но это устройство программы, а не забота человека. Ему выдаётся один файл;
//! кем быть в этот раз, программа решает сама по своим аргументам
//! ([`args`]), а права запрашивает тогда и только тогда, когда они нужны
//! ([`penguin_platform::run_elevated`]).
//!
//! # Консоль
//!
//! Файл собран как **оконный**: иначе двойной щелчок открывал бы чёрное окно
//! консоли рядом с интерфейсом. Оконная программа своей консоли не имеет, и
//! `penguin doctor`, запущенный из терминала, печатал бы в пустоту. Лечится
//! это подключением к консоли **родителя** — см. [`console`].

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// В исполняемом крейте `pub` не образует публичного API — он лишь открывает
// элемент соседним модулям.
#![allow(unreachable_pub)]

mod args;
mod console;
mod logging;
mod service;

use anyhow::{Context, Result};
use args::{Cli, Command, ServiceCommand};
use clap::Parser;

fn main() -> Result<()> {
    let mut cli = Cli::parse();

    // До первой печати: подключаться к консоли родителя надо раньше, чем в неё
    // что-то пойдёт.
    if cli.writes_to_console() {
        console::attach_to_parent();
    }
    prepare_arguments(&mut cli)?;

    // Права спрашиваются один раз и заранее — до того, как команда начнёт
    // работать и упрётся в отказ на середине.
    if cli.needs_elevation() && !penguin_platform::is_elevated() {
        return elevate_and_exit(&cli);
    }

    let _guard = logging::init(&cli);

    match &cli.command {
        // --- служба ---
        Some(Command::Service(command)) => {
            service::run(command, cli.controller_uid, cli.import_config.as_deref())
        }

        // --- терминал ---
        Some(Command::Client(command)) => {
            penguin_cli::run(command, cli.config_dir.as_deref(), cli.json)
        }

        // --- сама служба ---
        None if cli.service => penguin_daemon::service::run_as_service(cli.config_dir),
        None if cli.foreground => {
            penguin_daemon::runtime::run_foreground(cli.config_dir, cli.verbose)
        }

        // --- окно ---
        None => penguin_gui::run().context("окно не открылось"),
    }
}

/// Capture user-specific values before pkexec/osascript replace the environment.
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
        // Never take the elevated account's HOME as the import source.
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
    // Отказ в окне UAC — не сбой программы, а решение человека. Сказать о нём
    // надо, а падать с ошибкой незачем.
    anyhow::bail!("нужны права администратора");
}

/// Аргументы, с которыми себя перезапустить.
///
/// Свободная функция с тестом: потерянный здесь `--config-dir` означает
/// службу, поставленную не для того каталога настроек, который правил человек.
fn elevated_arguments(cli: &Cli) -> Vec<String> {
    let mut arguments = vec!["service".to_owned()];

    arguments.push(
        match cli.command {
            Some(Command::Service(ServiceCommand::Ensure)) => "ensure",
            Some(Command::Service(ServiceCommand::Install)) => "install",
            Some(Command::Service(ServiceCommand::Uninstall)) => "uninstall",
            Some(Command::Service(ServiceCommand::Restart)) => "restart",
            Some(Command::Service(ServiceCommand::Start)) => "start",
            Some(Command::Service(ServiceCommand::Stop)) => "stop",
            // Сюда попадают только команды, которым нужны права; остальные
            // отсеяны в `needs_elevation`.
            _ => "status",
        }
        .to_owned(),
    );

    if let Some(dir) = &cli.config_dir {
        arguments.push("--config-dir".to_owned());
        // Без кавычек: заключить путь с пробелом в них — забота той системы,
        // которая передаёт аргументы одной строкой
        // ([`penguin_platform::run_elevated`]). Там, где программа
        // запускается напрямую, кавычка стала бы частью имени каталога.
        arguments.push(dir.display().to_string());
    }
    if cli.verbose {
        arguments.push("--verbose".to_owned());
    }
    if let Some(uid) = cli.controller_uid {
        arguments.extend(["--controller-uid".to_owned(), uid.to_string()]);
    }
    if let Some(path) = &cli.import_config {
        arguments.push("--import-config".to_owned());
        arguments.push(path.display().to_string());
    }

    arguments
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("разбирается")
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
        // Потерянный каталог означает службу, поставленную не для тех
        // настроек, которые правил человек.
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
        // Путь пользователя почти всегда содержит пробел. Кавычки ему здесь
        // не ставятся: их поставит та система, которая передаёт аргументы
        // одной строкой, — а там, где программа запускается напрямую, кавычка
        // стала бы частью имени каталога.
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
        let arguments = elevated_arguments(&original);
        let reparsed = Cli::try_parse_from(std::iter::once("penguin".to_owned()).chain(arguments))
            .expect("arguments");
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
