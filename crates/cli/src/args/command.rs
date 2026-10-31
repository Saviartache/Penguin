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
    /// Подписка Amnezia: серверы по ключу `vpn://`.
    Subscription(SubscriptionCommand),
    /// Страна серверов `хост:порт` по базе GeoIP.
    Geoip(Vec<String>),
    /// Развёртывание сервера по SSH.
    Deploy(DeployCommand),
}

/// Что развернуть.
#[derive(Debug, PartialEq, Eq)]
pub enum DeployCommand {
    /// Сервер Pingwin; запрос — JSON на stdin.
    Pingwin,
}

/// Команды подписки.
#[derive(Debug, PartialEq, Eq)]
pub enum SubscriptionCommand {
    /// Забрать серверы у шлюза; без ключа — обновить все заведённые.
    Refresh {
        /// Ключ подписки `vpn://…`.
        key: Option<String>,
        /// Обновить только одну заведённую подписку по идентификатору.
        id: Option<String>,
        /// Пометить запрос событием подключения (`is_connect_event`).
        connect_event: bool,
        /// Взять второй (dev) ключ шлюза вместо первого — какой боевой, не проверено.
        dev: bool,
        /// Адрес шлюза вместо боевого (для отладки и dev-шлюза).
        endpoint: Option<String>,
        /// Обновить только одну локацию по коду страны (иначе — все).
        country: Option<String>,
    },
    /// Показать заведённые подписки.
    List,
    /// Убрать подписку и её профили по идентификатору.
    Remove {
        /// Идентификатор подписки.
        id: String,
    },
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
pub const NAMES: [&str; 9] = [
    "socks",
    "http",
    "profiles",
    "rules",
    "doctor",
    "update",
    "subscription",
    "geoip",
    "deploy",
];

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
        "subscription" => subscription(lx).map(|p| p.map(Command::Subscription)),
        "geoip" => geoip(lx).map(|p| p.map(Command::Geoip)),
        "deploy" => deploy(lx).map(|p| p.map(Command::Deploy)),
        _ => Err(ArgsError::UnknownCommand(name)),
    }
}

fn deploy(mut lx: Lexer) -> Result<Parsed<DeployCommand>, ArgsError> {
    subcommand(&mut lx, "deploy", help::DEPLOY)?.and_then(|name| match name.as_str() {
        "pingwin" => leaf(lx, help::DEPLOY_PINGWIN, DeployCommand::Pingwin),
        _ => Err(ArgsError::UnknownCommand(name)),
    })
}

fn geoip(mut lx: Lexer) -> Result<Parsed<Vec<String>>, ArgsError> {
    let mut servers = Vec::new();
    let wanted = walk(&mut lx, unknown_flag, |word| {
        servers.push(word);
        Ok(())
    })?;
    if wanted {
        return Ok(Parsed::Print(help::GEOIP));
    }
    Ok(Parsed::Run(servers))
}

fn subscription(mut lx: Lexer) -> Result<Parsed<SubscriptionCommand>, ArgsError> {
    subcommand(&mut lx, "subscription", help::SUBSCRIPTION)?.and_then(|name| match name.as_str() {
        "refresh" => refresh(lx),
        "list" => leaf(lx, help::SUBSCRIPTION_LIST, SubscriptionCommand::List),
        "remove" => remove(lx),
        _ => Err(ArgsError::UnknownCommand(name)),
    })
}

fn refresh(mut lx: Lexer) -> Result<Parsed<SubscriptionCommand>, ArgsError> {
    let mut key = None;
    let mut id = None;
    let mut connect_event = false;
    let mut dev = false;
    let mut endpoint = None;
    let mut country = None;
    let wanted = walk(
        &mut lx,
        |flag, lx| match flag {
            "--id" => {
                id = Some(lx.value(flag)?);
                Ok(())
            }
            "--connect-event" => {
                connect_event = true;
                Ok(())
            }
            "--dev" => {
                dev = true;
                Ok(())
            }
            "--endpoint" => {
                endpoint = Some(lx.value(flag)?);
                Ok(())
            }
            "--country" => {
                country = Some(lx.value(flag)?);
                Ok(())
            }
            _ => Err(ArgsError::UnknownOption(flag.to_owned())),
        },
        |word| {
            if key.is_some() {
                return Err(ArgsError::Unexpected(word));
            }
            key = Some(word);
            Ok(())
        },
    )?;
    Ok(done(
        wanted,
        help::SUBSCRIPTION_REFRESH,
        SubscriptionCommand::Refresh {
            key,
            id,
            connect_event,
            dev,
            endpoint,
            country,
        },
    ))
}

fn remove(mut lx: Lexer) -> Result<Parsed<SubscriptionCommand>, ArgsError> {
    let mut id = None;
    let wanted = walk(&mut lx, unknown_flag, |word| {
        if id.is_some() {
            return Err(ArgsError::Unexpected(word));
        }
        id = Some(word);
        Ok(())
    })?;
    if wanted {
        return Ok(Parsed::Print(help::SUBSCRIPTION_REMOVE));
    }
    let id = id.ok_or(ArgsError::MissingArgument("<ID>"))?;
    Ok(Parsed::Run(SubscriptionCommand::Remove { id }))
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
    fn subscription_subcommands() {
        assert_eq!(
            run(&["subscription", "refresh"]),
            Ok(Command::Subscription(SubscriptionCommand::Refresh {
                key: None,
                id: None,
                connect_event: false,
                dev: false,
                endpoint: None,
                country: None,
            }))
        );
        assert_eq!(
            run(&["subscription", "refresh", "vpn://abc", "--dev"]),
            Ok(Command::Subscription(SubscriptionCommand::Refresh {
                key: Some("vpn://abc".into()),
                id: None,
                connect_event: false,
                dev: true,
                endpoint: None,
                country: None,
            }))
        );
        assert_eq!(
            run(&[
                "subscription",
                "refresh",
                "--id",
                "amnezia-1",
                "--connect-event",
                "--country",
                "nl"
            ]),
            Ok(Command::Subscription(SubscriptionCommand::Refresh {
                key: None,
                id: Some("amnezia-1".into()),
                connect_event: true,
                dev: false,
                endpoint: None,
                country: Some("nl".into()),
            }))
        );
        assert_eq!(
            run(&["subscription", "remove", "amnezia-1"]),
            Ok(Command::Subscription(SubscriptionCommand::Remove {
                id: "amnezia-1".into()
            }))
        );
        assert_eq!(
            run(&["subscription", "remove"]),
            Err(ArgsError::MissingArgument("<ID>"))
        );
        assert_eq!(
            run(&["subscription"]),
            Err(ArgsError::MissingCommand("subscription"))
        );
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
    fn geoip_takes_any_number_of_servers() {
        assert_eq!(
            run(&["geoip", "example.com:443", "203.0.113.5:51820"]),
            Ok(Command::Geoip(vec![
                "example.com:443".to_owned(),
                "203.0.113.5:51820".to_owned()
            ]))
        );
        assert_eq!(run(&["geoip"]), Ok(Command::Geoip(Vec::new())));
    }

    #[test]
    fn deploy_subcommands() {
        assert_eq!(
            run(&["deploy", "pingwin"]),
            Ok(Command::Deploy(DeployCommand::Pingwin))
        );
        assert_eq!(run(&["deploy"]), Err(ArgsError::MissingCommand("deploy")));
        assert_eq!(
            run(&["deploy", "pingwin", "--password", "x"]),
            Err(ArgsError::UnknownOption("--password".into()))
        );
        assert!(help(&["deploy", "pingwin", "-h"]).contains("deploy pingwin"));
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
