//! Аргументы: кем программе быть в этот раз.
//!
//! | Запуск | Роль |
//! |---|---|
//! | двойной щелчок, `penguin` | окно |
//! | `penguin --tray` | окно, свёрнутое в лоток |
//! | `penguin doctor`, `penguin socks`, … | терминал |
//! | `penguin service …` | управление службой |
//! | `penguin --service` | служба, запущенная диспетчером |
//! | `penguin --foreground` | служба на переднем плане, для отладки |
//!
//! Без аргументов — окно: программу запускают двойным щелчком, а не из терминала.

use std::path::PathBuf;

use penguin_cli::args::{self as client, ArgsError, Lexer, Parsed, Token};

use crate::help;

/// Разобранная командная строка.
#[derive(Debug, Default)]
pub struct Cli {
    /// Каталог с настройками.
    pub config_dir: Option<PathBuf>,
    /// Пользователь рабочего стола, одобренный помощником службы (только Unix).
    pub controller_uid: Option<u32>,
    /// Прежние настройки; импортируются только при первой установке.
    pub import_config: Option<PathBuf>,
    /// Подробный журнал.
    pub verbose: bool,
    /// Вывод в JSON.
    pub json: bool,
    /// Запущено диспетчером служб.
    pub service: bool,
    /// Служба на переднем плане.
    pub foreground: bool,
    /// Окно, свёрнутое в лоток.
    pub tray: bool,
    /// Команда; без неё — окно.
    pub command: Option<Command>,
}

/// Команды программы.
#[derive(Debug)]
pub enum Command {
    /// Команды терминала: плоско, `penguin doctor`, а не `penguin cli doctor`.
    Client(client::Command),
    /// Служба: установка, запуск, состояние.
    Service(ServiceCommand),
}

/// Что сделать со службой.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceCommand {
    /// Поставить и запустить.
    Ensure,
    /// Поставить.
    Install,
    /// Убрать.
    Uninstall,
    /// Перезапустить.
    Restart,
    /// Запустить.
    Start,
    /// Остановить.
    Stop,
    /// Показать состояние.
    Status,
}

const SERVICE_COMMANDS: [(&str, ServiceCommand, &str); 7] = [
    ("ensure", ServiceCommand::Ensure, help::ENSURE),
    ("install", ServiceCommand::Install, help::INSTALL),
    ("uninstall", ServiceCommand::Uninstall, help::UNINSTALL),
    ("restart", ServiceCommand::Restart, help::RESTART),
    ("start", ServiceCommand::Start, help::START),
    ("stop", ServiceCommand::Stop, help::STOP),
    ("status", ServiceCommand::Status, help::STATUS),
];

impl Cli {
    /// Нужны ли этому запуску права администратора.
    pub fn needs_elevation(&self) -> bool {
        matches!(
            self.command,
            Some(Command::Service(
                ServiceCommand::Ensure
                    | ServiceCommand::Install
                    | ServiceCommand::Uninstall
                    | ServiceCommand::Restart
                    | ServiceCommand::Start
                    | ServiceCommand::Stop
            ))
        )
    }

    /// Печатает ли запуск в терминал; окно и служба — нет.
    pub fn writes_to_console(&self) -> bool {
        self.command.is_some() || self.foreground
    }
}

/// Разбирает аргументы процесса.
pub fn from_env() -> Result<Parsed<Cli>, ArgsError> {
    let args = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string().map_err(|_| ArgsError::NotUnicode))
        .collect::<Result<Vec<_>, _>>()?;
    parse(args)
}

/// Разбирает аргументы без имени программы. Общие флаги допустимы где угодно.
pub fn parse(args: Vec<String>) -> Result<Parsed<Cli>, ArgsError> {
    let mut cli = Cli::default();
    let mut lx = Lexer::new(args);
    let mut rest = Vec::new();
    while let Some(token) = lx.next_token()? {
        match token {
            Token::Flag(flag) => match flag.as_str() {
                "--config-dir" => cli.config_dir = Some(lx.value(&flag)?.into()),
                "--controller-uid" => cli.controller_uid = Some(lx.parsed(&flag)?),
                "--import-config" => cli.import_config = Some(lx.value(&flag)?.into()),
                "-v" | "--verbose" => cli.verbose = true,
                "--json" => cli.json = true,
                "--service" => cli.service = true,
                "--foreground" => cli.foreground = true,
                "--tray" => cli.tray = true,
                _ => rest.push(lx.passthrough(&flag)),
            },
            Token::Word(word) => rest.push(word),
        }
    }
    Ok(command(rest)?.map(|command| {
        cli.command = command;
        cli
    }))
}

fn command(mut rest: Vec<String>) -> Result<Parsed<Option<Command>>, ArgsError> {
    let Some(first) = rest.first().map(String::as_str) else {
        return Ok(Parsed::Run(None));
    };
    match first {
        "-h" | "--help" => Ok(Parsed::Print(help::TOP)),
        "-V" | "--version" => Ok(Parsed::Print(help::VERSION)),
        "help" if rest.len() == 1 => Ok(Parsed::Print(help::TOP)),
        "help" => {
            rest.remove(0);
            rest.push("--help".to_owned());
            command(rest)
        }
        "service" => {
            rest.remove(0);
            Ok(service(rest)?.map(|command| Some(Command::Service(command))))
        }
        name if client::NAMES.contains(&name) => {
            Ok(client::parse(rest)?.map(|command| Some(Command::Client(command))))
        }
        flag if flag.starts_with('-') => Err(ArgsError::UnknownOption(flag.to_owned())),
        name => Err(ArgsError::UnknownCommand(name.to_owned())),
    }
}

fn service(rest: Vec<String>) -> Result<Parsed<ServiceCommand>, ArgsError> {
    let mut lx = Lexer::new(rest);
    let name = match lx.next_token()? {
        Some(Token::Word(name)) => name,
        Some(Token::Flag(flag)) if matches!(flag.as_str(), "-h" | "--help") => {
            return Ok(Parsed::Print(help::SERVICE));
        }
        Some(Token::Flag(flag)) => return Err(ArgsError::UnknownOption(flag)),
        None => return Err(ArgsError::MissingCommand("service")),
    };
    let Some(&(_, command, text)) = SERVICE_COMMANDS.iter().find(|(known, ..)| *known == name)
    else {
        return Err(ArgsError::UnknownCommand(name));
    };
    client::leaf(lx, text, command)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> Cli {
        match parse(args.iter().skip(1).map(|arg| (*arg).to_owned()).collect()) {
            Ok(Parsed::Run(cli)) => cli,
            other => panic!("не запуск: {other:?}"),
        }
    }

    fn printed(args: &[&str]) -> &'static str {
        match parse(args.iter().map(|arg| (*arg).to_owned()).collect()) {
            Ok(Parsed::Print(text)) => text,
            other => panic!("не справка: {other:?}"),
        }
    }

    fn error(args: &[&str]) -> ArgsError {
        parse(args.iter().map(|arg| (*arg).to_owned()).collect()).expect_err("ошибка")
    }

    #[test]
    fn no_arguments_means_the_window() {
        // Программу запускают двойным щелчком.
        let cli = cli(&["penguin"]);
        assert!(cli.command.is_none());
        assert!(!cli.service);
    }

    #[test]
    fn the_tray_flag_still_means_the_window() {
        let cli = cli(&["penguin", "--tray"]);
        assert!(cli.tray);
        assert!(cli.command.is_none());
        assert!(!cli.needs_elevation());
        assert!(!cli.writes_to_console());
    }

    #[test]
    fn terminal_commands_stay_flat() {
        let cli = cli(&["penguin", "doctor"]);
        assert!(matches!(
            cli.command,
            Some(Command::Client(client::Command::Doctor))
        ));
    }

    #[test]
    fn socks_keeps_its_loopback_default() {
        let cli = cli(&["penguin", "socks"]);
        let Some(Command::Client(client::Command::Socks(args))) = cli.command else {
            panic!("не та команда")
        };
        // Прокси, открытый наружу, — открытый прокси для всей сети.
        assert!(args.listen.ip().is_loopback());
        assert_eq!(args.listen.port(), 1080);
    }

    #[test]
    fn explain_takes_a_process_and_a_destination() {
        let cli = cli(&[
            "penguin",
            "rules",
            "explain",
            "example.com:443",
            "--process",
            "chrome.exe",
        ]);
        let Some(Command::Client(client::Command::Rules(client::RulesCommand::Explain {
            destination,
            process,
            udp,
        }))) = cli.command
        else {
            panic!("не та команда")
        };
        assert_eq!(destination, "example.com:443");
        assert_eq!(process.as_deref(), Some("chrome.exe"));
        assert!(!udp);
    }

    #[test]
    fn global_flags_work_anywhere() {
        assert!(cli(&["penguin", "doctor", "--json"]).json);
        let cli = cli(&["penguin", "--config-dir=/a b", "rules", "list", "-v"]);
        assert_eq!(cli.config_dir, Some(PathBuf::from("/a b")));
        assert!(cli.verbose);
        assert!(matches!(
            cli.command,
            Some(Command::Client(client::Command::Rules(
                client::RulesCommand::List
            )))
        ));
    }

    #[test]
    fn client_flags_with_inline_values_reach_the_command() {
        let cli = cli(&["penguin", "socks", "--listen=127.0.0.1:9", "--json"]);
        let Some(Command::Client(client::Command::Socks(args))) = cli.command else {
            panic!("не та команда")
        };
        assert_eq!(args.listen.port(), 9);
        assert!(cli.json);
    }

    #[test]
    fn the_service_dispatcher_flag_is_recognised() {
        let cli = cli(&["penguin", "--service"]);
        assert!(cli.service);
        assert!(cli.command.is_none());
    }

    #[test]
    fn service_options_are_read() {
        let cli = cli(&[
            "penguin",
            "service",
            "ensure",
            "--controller-uid",
            "501",
            "--import-config",
            "/x/y",
        ]);
        assert_eq!(cli.controller_uid, Some(501));
        assert_eq!(cli.import_config, Some(PathBuf::from("/x/y")));
        assert!(matches!(
            cli.command,
            Some(Command::Service(ServiceCommand::Ensure))
        ));
        assert!(matches!(
            error(&["--controller-uid", "x"]),
            ArgsError::InvalidValue { .. }
        ));
    }

    #[test]
    fn only_service_commands_ask_for_rights() {
        // Лишний запрос UAC раздражает, а пропущенный — роняет команду отказом.
        for args in [
            vec!["penguin", "service", "ensure"],
            vec!["penguin", "service", "install"],
            vec!["penguin", "service", "start"],
            vec!["penguin", "service", "stop"],
            vec!["penguin", "service", "uninstall"],
            vec!["penguin", "service", "restart"],
        ] {
            assert!(
                cli(&args).needs_elevation(),
                "{args:?} обязана просить права"
            );
        }

        for args in [
            vec!["penguin"],
            vec!["penguin", "doctor"],
            vec!["penguin", "socks"],
            vec!["penguin", "service", "status"],
        ] {
            assert!(!cli(&args).needs_elevation(), "{args:?} права не нужны");
        }
    }

    #[test]
    fn only_terminal_roles_print() {
        // Без подключения к консоли родителя вывод оконной программы не виден.
        assert!(!cli(&["penguin"]).writes_to_console());
        assert!(!cli(&["penguin", "--service"]).writes_to_console());
        assert!(cli(&["penguin", "doctor"]).writes_to_console());
        assert!(cli(&["penguin", "--foreground"]).writes_to_console());
    }

    #[test]
    fn help_and_version() {
        assert_eq!(printed(&["--help"]), help::TOP);
        assert_eq!(printed(&["-h"]), help::TOP);
        assert_eq!(printed(&["help"]), help::TOP);
        assert_eq!(printed(&["-V"]), help::VERSION);
        assert_eq!(printed(&["--version"]), help::VERSION);
        assert_eq!(printed(&["service", "--help"]), help::SERVICE);
        assert_eq!(printed(&["service", "ensure", "-h"]), help::ENSURE);
        assert_eq!(printed(&["help", "service", "stop"]), help::STOP);
        assert!(printed(&["doctor", "--help"]).contains("penguin doctor"));
    }

    #[test]
    fn mistakes_are_reported() {
        assert_eq!(error(&["bogus"]), ArgsError::UnknownCommand("bogus".into()));
        assert_eq!(
            error(&["--bogus"]),
            ArgsError::UnknownOption("--bogus".into())
        );
        assert_eq!(error(&["service"]), ArgsError::MissingCommand("service"));
        assert_eq!(
            error(&["service", "bogus"]),
            ArgsError::UnknownCommand("bogus".into())
        );
        assert_eq!(
            error(&["service", "stop", "now"]),
            ArgsError::Unexpected("now".into())
        );
        assert_eq!(
            error(&["--config-dir"]),
            ArgsError::MissingValue("--config-dir".into())
        );
    }
}
