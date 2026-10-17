//! Команды терминала и их разбор.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::help;
use super::lexer::{ArgsError, Lexer, Parsed, Token};

/// Команды клиента.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Локальный SOCKS5 поверх выбранного профиля.
    Socks(SocksArgs),
    /// Локальный HTTP-прокси поверх выбранного профиля.
    Http(SocksArgs),
    /// Профили: список и проверка.
    Profiles(ProfilesCommand),
    /// Правила маршрутизации.
    Rules(RulesCommand),
    /// Проверка окружения: настройки, профили, права.
    Doctor,
    /// Обновление с GitHub.
    Update(UpdateCommand),
}

/// Команды обновления.
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateCommand {
    /// Спросить GitHub, есть ли выпуск новее.
    Check,
    /// Скачать выпуск, сверить SHA-256 и заменить исполняемый файл.
    Install,
}

/// Параметры локального прокси.
#[derive(Debug, PartialEq, Eq)]
pub struct SocksArgs {
    /// Профиль. По умолчанию — активный из настроек.
    pub profile: Option<String>,
    /// Где слушать.
    pub listen: SocketAddr,
    /// Не применять правила: весь трафик в тоннель.
    pub no_rules: bool,
}

impl Default for SocksArgs {
    fn default() -> Self {
        Self {
            profile: None,
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080),
            no_rules: false,
        }
    }
}

/// Команды профилей.
#[derive(Debug, PartialEq, Eq)]
pub enum ProfilesCommand {
    /// Список профилей.
    List,
    /// Проверить настройки профиля, не подключаясь.
    Check {
        /// Профиль. По умолчанию — все.
        profile: Option<String>,
    },
}

/// Команды правил.
#[derive(Debug, PartialEq, Eq)]
pub enum RulesCommand {
    /// Список правил в порядке разбора.
    List,
    /// Объяснить, что случится с таким соединением.
    Explain {
        /// Куда: `example.com:443` или `1.2.3.4:443`.
        destination: String,
        /// Путь к приложению или имя исполняемого файла.
        process: Option<String>,
        /// Считать соединение UDP, а не TCP.
        udp: bool,
    },
}

/// Имена команд этого модуля.
pub const NAMES: [&str; 6] = ["socks", "http", "profiles", "rules", "doctor", "update"];

/// Разбирает команду; первым идёт её имя, общие флаги уже убраны.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Parsed<Command>, ArgsError> {
    let mut lx = Lexer::new(args);
    let Some(Token::Word(name)) = lx.next_token()? else {
        return Err(ArgsError::MissingCommand("penguin"));
    };
    match name.as_str() {
        "socks" => proxy(lx, help::SOCKS).map(|p| p.map(Command::Socks)),
        "http" => proxy(lx, help::HTTP).map(|p| p.map(Command::Http)),
        "profiles" => profiles(lx).map(|p| p.map(Command::Profiles)),
        "rules" => rules(lx).map(|p| p.map(Command::Rules)),
        "doctor" => leaf(lx, help::DOCTOR, Command::Doctor),
        "update" => update(lx).map(|p| p.map(Command::Update)),
        _ => Err(ArgsError::UnknownCommand(name)),
    }
}

fn update(mut lx: Lexer) -> Result<Parsed<UpdateCommand>, ArgsError> {
    subcommand(&mut lx, "update", help::UPDATE)?.and_then(|name| match name.as_str() {
        "check" => leaf(lx, help::UPDATE_CHECK, UpdateCommand::Check),
        "install" => leaf(lx, help::UPDATE_INSTALL, UpdateCommand::Install),
        _ => Err(ArgsError::UnknownCommand(name)),
    })
}

fn proxy(mut lx: Lexer, help: &'static str) -> Result<Parsed<SocksArgs>, ArgsError> {
    let mut args = SocksArgs::default();
    let wanted = walk(
        &mut lx,
        |flag, lx| {
            match flag {
                "-p" | "--profile" => args.profile = Some(lx.value(flag)?),
                "-l" | "--listen" => args.listen = lx.parsed(flag)?,
                "--no-rules" => args.no_rules = true,
                _ => return Err(ArgsError::UnknownOption(flag.to_owned())),
            }
            Ok(())
        },
        unexpected,
    )?;
    Ok(done(wanted, help, args))
}

fn profiles(mut lx: Lexer) -> Result<Parsed<ProfilesCommand>, ArgsError> {
    subcommand(&mut lx, "profiles", help::PROFILES)?.and_then(|name| match name.as_str() {
        "list" => leaf(lx, help::PROFILES_LIST, ProfilesCommand::List),
        "check" => check(lx),
        _ => Err(ArgsError::UnknownCommand(name)),
    })
}

fn check(mut lx: Lexer) -> Result<Parsed<ProfilesCommand>, ArgsError> {
    let mut profile = None;
    let wanted = walk(&mut lx, unknown_flag, |word| {
        if profile.is_some() {
            return Err(ArgsError::Unexpected(word));
        }
        profile = Some(word);
        Ok(())
    })?;
    Ok(done(
        wanted,
        help::PROFILES_CHECK,
        ProfilesCommand::Check { profile },
    ))
}

fn rules(mut lx: Lexer) -> Result<Parsed<RulesCommand>, ArgsError> {
    subcommand(&mut lx, "rules", help::RULES)?.and_then(|name| match name.as_str() {
        "list" => leaf(lx, help::RULES_LIST, RulesCommand::List),
        "explain" => explain(lx),
        _ => Err(ArgsError::UnknownCommand(name)),
    })
}

fn explain(mut lx: Lexer) -> Result<Parsed<RulesCommand>, ArgsError> {
    let (mut destination, mut process, mut udp) = (None, None, false);
    let wanted = walk(
        &mut lx,
        |flag, lx| {
            match flag {
                "-p" | "--process" => process = Some(lx.value(flag)?),
                "--udp" => udp = true,
                _ => return Err(ArgsError::UnknownOption(flag.to_owned())),
            }
            Ok(())
        },
        |word| {
            if destination.is_some() {
                return Err(ArgsError::Unexpected(word));
            }
            destination = Some(word);
            Ok(())
        },
    )?;
    if wanted {
        return Ok(Parsed::Print(help::RULES_EXPLAIN));
    }
    let destination = destination.ok_or(ArgsError::MissingArgument("<АДРЕС>"))?;
    Ok(Parsed::Run(RulesCommand::Explain {
        destination,
        process,
        udp,
    }))
}

/// Команда без собственных флагов и аргументов: остаток — только `--help`.
pub fn leaf<T>(mut lx: Lexer, help: &'static str, value: T) -> Result<Parsed<T>, ArgsError> {
    let wanted = walk(&mut lx, unknown_flag, unexpected)?;
    Ok(done(wanted, help, value))
}

/// Имя подкоманды группы либо её справка.
fn subcommand(
    lx: &mut Lexer,
    group: &'static str,
    help: &'static str,
) -> Result<Parsed<String>, ArgsError> {
    match lx.next_token()? {
        Some(Token::Word(name)) => Ok(Parsed::Run(name)),
        Some(Token::Flag(flag)) if is_help(&flag) => Ok(Parsed::Print(help)),
        Some(Token::Flag(flag)) => Err(ArgsError::UnknownOption(flag)),
        None => Err(ArgsError::MissingCommand(group)),
    }
}

/// Читает аргументы до конца; `true` — попросили справку.
fn walk(
    lx: &mut Lexer,
    mut on_flag: impl FnMut(&str, &mut Lexer) -> Result<(), ArgsError>,
    mut on_word: impl FnMut(String) -> Result<(), ArgsError>,
) -> Result<bool, ArgsError> {
    while let Some(token) = lx.next_token()? {
        match token {
            Token::Flag(flag) if is_help(&flag) => return Ok(true),
            Token::Flag(flag) => on_flag(&flag, lx)?,
            Token::Word(word) => on_word(word)?,
        }
    }
    Ok(false)
}

fn done<T>(wanted: bool, help: &'static str, value: T) -> Parsed<T> {
    if wanted {
        Parsed::Print(help)
    } else {
        Parsed::Run(value)
    }
}

fn is_help(flag: &str) -> bool {
    matches!(flag, "-h" | "--help")
}

fn unknown_flag(flag: &str, _: &mut Lexer) -> Result<(), ArgsError> {
    Err(ArgsError::UnknownOption(flag.to_owned()))
}

fn unexpected(word: String) -> Result<(), ArgsError> {
    Err(ArgsError::Unexpected(word))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Command, ArgsError> {
        match parse(args.iter().map(|arg| (*arg).to_owned()))? {
            Parsed::Run(command) => Ok(command),
            Parsed::Print(_) => panic!("справка вместо команды"),
        }
    }

    fn help(args: &[&str]) -> &'static str {
        match parse(args.iter().map(|arg| (*arg).to_owned())).expect("разбирается") {
            Parsed::Print(text) => text,
            Parsed::Run(_) => panic!("команда вместо справки"),
        }
    }

    #[test]
    fn socks_defaults_to_loopback() {
        // Прокси, открытый наружу, — открытый прокси для всей сети.
        let Ok(Command::Socks(args)) = run(&["socks"]) else {
            panic!("не та команда")
        };
        assert_eq!(args, SocksArgs::default());
        assert!(args.listen.ip().is_loopback());
        assert_eq!(args.listen.port(), 1080);
    }

    #[test]
    fn http_takes_all_options() {
        let command = run(&[
            "http",
            "-p",
            "main",
            "--listen=127.0.0.1:8080",
            "--no-rules",
        ]);
        assert_eq!(
            command,
            Ok(Command::Http(SocksArgs {
                profile: Some("main".into()),
                listen: "127.0.0.1:8080".parse().expect("адрес"),
                no_rules: true,
            }))
        );
    }

    #[test]
    fn bad_listen_is_reported() {
        assert!(matches!(
            run(&["socks", "--listen", "x"]),
            Err(ArgsError::InvalidValue { .. })
        ));
    }

    #[test]
    fn profiles_subcommands() {
        assert_eq!(
            run(&["profiles", "list"]),
            Ok(Command::Profiles(ProfilesCommand::List))
        );
        assert_eq!(
            run(&["profiles", "check"]),
            Ok(Command::Profiles(ProfilesCommand::Check { profile: None }))
        );
        assert_eq!(
            run(&["profiles", "check", "main"]),
            Ok(Command::Profiles(ProfilesCommand::Check {
                profile: Some("main".into())
            }))
        );
        assert_eq!(
            run(&["profiles", "check", "a", "b"]),
            Err(ArgsError::Unexpected("b".into()))
        );
        assert_eq!(
            run(&["profiles"]),
            Err(ArgsError::MissingCommand("profiles"))
        );
    }

    #[test]
    fn rules_subcommands() {
        assert_eq!(
            run(&["rules", "list"]),
            Ok(Command::Rules(RulesCommand::List))
        );
        assert_eq!(
            run(&[
                "rules",
                "explain",
                "example.com:443",
                "--process",
                "chrome.exe"
            ]),
            Ok(Command::Rules(RulesCommand::Explain {
                destination: "example.com:443".into(),
                process: Some("chrome.exe".into()),
                udp: false,
            }))
        );
        assert_eq!(
            run(&["rules", "explain", "--udp", "1.2.3.4:53"]),
            Ok(Command::Rules(RulesCommand::Explain {
                destination: "1.2.3.4:53".into(),
                process: None,
                udp: true,
            }))
        );
        assert_eq!(
            run(&["rules", "explain"]),
            Err(ArgsError::MissingArgument("<АДРЕС>"))
        );
    }

    #[test]
    fn doctor_takes_nothing() {
        assert_eq!(run(&["doctor"]), Ok(Command::Doctor));
        assert_eq!(
            run(&["doctor", "extra"]),
            Err(ArgsError::Unexpected("extra".into()))
        );
        assert_eq!(
            run(&["doctor", "--x"]),
            Err(ArgsError::UnknownOption("--x".into()))
        );
    }

    #[test]
    fn update_subcommands() {
        assert_eq!(
            run(&["update", "check"]),
            Ok(Command::Update(UpdateCommand::Check))
        );
        assert_eq!(
            run(&["update", "install"]),
            Ok(Command::Update(UpdateCommand::Install))
        );
        assert_eq!(run(&["update"]), Err(ArgsError::MissingCommand("update")));
        assert_eq!(
            run(&["update", "check", "x"]),
            Err(ArgsError::Unexpected("x".into()))
        );
        assert!(help(&["update", "install", "-h"]).contains("update install"));
    }

    #[test]
    fn unknown_command_is_rejected() {
        assert_eq!(
            run(&["bogus"]),
            Err(ArgsError::UnknownCommand("bogus".into()))
        );
        assert_eq!(
            run(&["rules", "bogus"]),
            Err(ArgsError::UnknownCommand("bogus".into()))
        );
    }

    #[test]
    fn every_command_has_help() {
        for name in NAMES {
            assert!(help(&[name, "--help"]).contains(&format!("penguin {name}")));
        }
        assert!(help(&["profiles", "check", "-h"]).contains("profiles check"));
        assert!(help(&["rules", "explain", "-h"]).contains("rules explain"));
        assert!(help(&["rules", "-h"]).contains("explain"));
    }
}
