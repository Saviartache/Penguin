//! Запуск сервера Pingwin: разбор командной строки и ничего больше.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use penguin_pingwin::StaticKeyPair;
use penguin_pingwin_server::{Server, ServerConfig};

const HELP: &str = "\
Сервер протокола Pingwin

Использование: pingwin-server <КОМАНДА>

Команды:
  keygen  Печатает новую пару ключей: закрытый - в настройки сервера, открытый - в профиль клиента
  run     Слушает и обслуживает соединения
  check   Проверяет настройки и выходит, ничего не открывая
  link    Печатает ссылку-приглашение для клиента

Параметры run, check, link:
  -c, --config <ФАЙЛ>  Файл настроек

Параметры link:
  -u, --user <ИМЯ>     Чей профиль [по умолчанию: первый пользователь]
      --host <АДРЕС>   Адрес, по которому клиент придёт: example.com:443
      --sni <ИМЯ>      Имя в сертификате сервера [по умолчанию: пусто]
      --name <ИМЯ>     Имя профиля в клиенте [по умолчанию: Pingwin]

  -h, --help           Справка
";

/// Параметры `link`.
struct LinkArgs {
    user: Option<String>,
    host: String,
    sni: String,
    name: String,
}

enum Command {
    Keygen,
    Run(PathBuf),
    Check(PathBuf),
    Link(PathBuf, LinkArgs),
}

/// Значения флагов команды; неизвестный флаг - ошибка.
struct Flags(Vec<(String, String)>);

impl Flags {
    fn parse(args: impl Iterator<Item = String>, known: &[(&str, Option<&str>)]) -> Result<Self> {
        let mut args = args;
        let mut flags = Vec::new();
        while let Some(arg) = args.next() {
            let long = known
                .iter()
                .find(|(long, short)| arg == *long || Some(arg.as_str()) == *short)
                .map(|(long, _)| *long)
                .with_context(|| format!("неизвестный параметр `{arg}`"))?;
            let value = args
                .next()
                .with_context(|| format!("у `{arg}` нет значения"))?;
            flags.push((long.to_owned(), value));
        }
        Ok(Self(flags))
    }

    fn take(&mut self, long: &str) -> Option<String> {
        let at = self.0.iter().rposition(|(name, _)| name == long)?;
        Some(self.0.swap_remove(at).1)
    }

    fn required(&mut self, long: &str) -> Result<String> {
        self.take(long)
            .with_context(|| format!("не задан обязательный параметр `{long}`"))
    }
}

/// Разбирает командную строку; `None` - справка уже напечатана.
fn parse(mut args: impl Iterator<Item = String>) -> Result<Option<Command>> {
    let Some(command) = args.next() else {
        bail!("не указана команда\n\n{HELP}");
    };
    let config = ("--config", Some("-c"));
    let command = match command.as_str() {
        "-h" | "--help" | "help" => {
            print!("{HELP}");
            return Ok(None);
        }
        "keygen" => {
            if let Some(extra) = args.next() {
                bail!("неизвестный параметр `{extra}`");
            }
            Command::Keygen
        }
        "run" | "check" => {
            let mut flags = Flags::parse(args, &[config])?;
            let path = flags.required("--config")?.into();
            if command == "run" {
                Command::Run(path)
            } else {
                Command::Check(path)
            }
        }
        "link" => {
            let known = [
                config,
                ("--user", Some("-u")),
                ("--host", None),
                ("--sni", None),
                ("--name", None),
            ];
            let mut flags = Flags::parse(args, &known)?;
            let path = flags.required("--config")?.into();
            Command::Link(
                path,
                LinkArgs {
                    user: flags.take("--user"),
                    host: flags.required("--host")?,
                    sni: flags.take("--sni").unwrap_or_default(),
                    name: flags.take("--name").unwrap_or_else(|| "Pingwin".into()),
                },
            )
        }
        other => bail!("неизвестная команда `{other}`\n\n{HELP}"),
    };
    Ok(Some(command))
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match parse(std::env::args().skip(1))? {
        None => Ok(()),
        Some(Command::Keygen) => {
            keygen();
            Ok(())
        }
        Some(Command::Check(config)) => check(&config),
        Some(Command::Run(config)) => run(&config),
        Some(Command::Link(config, args)) => link(&config, &args),
    }
}

/// Печатает ссылку-приглашение.
fn link(path: &Path, args: &LinkArgs) -> Result<()> {
    let config = ServerConfig::load(path)?;
    let keys = config.keys()?;

    let user = match &args.user {
        Some(wanted) => config
            .users
            .iter()
            .find(|user| &user.name == wanted)
            .with_context(|| format!("в настройках нет пользователя `{wanted}`"))?,
        None => config
            .users
            .first()
            .context("в настройках нет ни одного пользователя")?,
    };

    let (address, port) = split_host_port(&args.host)?;
    println!(
        "{}",
        penguin_pingwin::link::build(&penguin_pingwin::link::LinkParams {
            host: &address,
            port,
            password: &user.password,
            server_public: &keys.public,
            sni: &args.sni,
            name: &args.name,
        })
    );
    Ok(())
}

/// Разбирает `example.com:443` и `[2001:db8::1]:443`; адрес чаще доменный.
fn split_host_port(raw: &str) -> Result<(String, u16)> {
    let raw = raw.trim();
    let (host, port) = raw
        .rsplit_once(':')
        .with_context(|| format!("в адресе `{raw}` нет порта"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port
        .parse()
        .with_context(|| format!("порт `{port}` не разбирается"))?;
    Ok((host.to_owned(), port))
}

/// Печатает новую пару ключей.
fn keygen() {
    let pair = StaticKeyPair::generate();
    println!("# закрытый ключ — в `key` файла настроек сервера");
    println!(
        "key = \"{}\"",
        penguin_core::base64::encode(&pair.secret_bytes())
    );
    println!();
    println!("# открытый ключ — в поле «Ключ сервера» профиля клиента");
    println!("{}", penguin_core::base64::encode(&pair.public));
}

/// Проверяет настройки.
fn check(path: &Path) -> Result<()> {
    let config = ServerConfig::load(path)?;
    let server = Server::new(config)?;
    println!("настройки верны");
    println!("открытый ключ сервера: {}", server.public_key());
    Ok(())
}

/// Слушает и обслуживает соединения.
fn run(path: &Path) -> Result<()> {
    let config = ServerConfig::load(path)?;
    let server = Arc::new(Server::new(config)?);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            // Новые соединения перестают приниматься, начатые доживают.
            server
                .run(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
        })
}
