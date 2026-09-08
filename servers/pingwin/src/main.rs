//! Запуск сервера Pingwin: разбор командной строки и ничего больше.
//!
//! ```text
//!   pingwin-server keygen                 новая пара ключей
//!   pingwin-server run --config s.toml    слушать и обслуживать
//!   pingwin-server check --config s.toml  проверить настройки и выйти
//!   pingwin-server link --config s.toml --host example.com:443
//!                                         ссылка-приглашение для клиента
//! ```
//!
//! Всё остальное — в библиотеке того же крейта (`src/lib.rs`), и там же
//! сказано, почему она отдельная.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use penguin_pingwin::StaticKeyPair;
use penguin_pingwin_server::{Server, ServerConfig};

/// Разбор командной строки.
#[derive(Debug, Parser)]
#[command(name = "pingwin-server", about = "Сервер протокола Pingwin")]
struct Cli {
    /// Что делать.
    #[command(subcommand)]
    command: Command,
}

/// Команды сервера.
#[derive(Debug, Subcommand)]
enum Command {
    /// Печатает новую пару ключей: закрытый — в настройки сервера, открытый —
    /// в профиль клиента.
    Keygen,
    /// Слушает и обслуживает соединения.
    Run {
        /// Файл настроек.
        #[arg(long, short)]
        config: PathBuf,
    },
    /// Проверяет настройки и выходит, ничего не открывая.
    Check {
        /// Файл настроек.
        #[arg(long, short)]
        config: PathBuf,
    },
    /// Печатает ссылку-приглашение для клиента.
    ///
    /// Собирается из тех же настроек, по которым работает сервер: переносить
    /// ключ и пароль руками — четыре шанса ошибиться в одной строке.
    Link {
        /// Файл настроек.
        #[arg(long, short)]
        config: PathBuf,
        /// Чей профиль. По умолчанию — первый пользователь из настроек.
        #[arg(long, short)]
        user: Option<String>,
        /// Адрес, по которому клиент придёт: `example.com:443`.
        ///
        /// Не берётся из `listen` намеренно: сервер слушает внутри
        /// контейнера, а клиент приходит снаружи, и совпадают эти два адреса
        /// далеко не всегда.
        #[arg(long)]
        host: String,
        /// Имя прикрытия, которое клиент поставит в SNI.
        #[arg(long, default_value = penguin_pingwin::config::DEFAULT_SNI)]
        sni: String,
        /// Имя профиля в клиенте.
        #[arg(long, default_value = "Pingwin")]
        name: String,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Command::Keygen => {
            keygen();
            Ok(())
        }
        Command::Check { config } => check(&config),
        Command::Run { config } => run(&config),
        Command::Link {
            config,
            user,
            host,
            sni,
            name,
        } => link(&config, user.as_deref(), &host, &sni, &name),
    }
}

/// Печатает ссылку-приглашение.
fn link(path: &Path, user: Option<&str>, host: &str, sni: &str, name: &str) -> Result<()> {
    let config = ServerConfig::load(path)?;
    let keys = config.keys()?;

    let user = match user {
        Some(wanted) => config
            .users
            .iter()
            .find(|user| user.name == wanted)
            .with_context(|| format!("в настройках нет пользователя `{wanted}`"))?,
        // Первый — не «какой попало»: у сервера на одного пользователя
        // выбирать не из чего, а спрашивать имя ради единственной строки
        // значит требовать его там, где оно ничего не решает.
        None => config
            .users
            .first()
            .context("в настройках нет ни одного пользователя")?,
    };

    let (address, port) = split_host_port(host)?;
    println!(
        "{}",
        penguin_pingwin::link::build(&penguin_pingwin::link::LinkParams {
            host: &address,
            port,
            password: &user.password,
            server_public: &keys.public,
            sni,
            name,
        })
    );
    Ok(())
}

/// Разбирает `example.com:443` и `[2001:db8::1]:443`.
///
/// Свой разбор, а не `SocketAddr`: адрес чаще всего доменный, и требовать
/// здесь числовой значило бы требовать его там, где его нет.
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
            server
                .run(async {
                    // Останов по Ctrl+C: соединения при этом не рвутся —
                    // перестаёт приниматься новое, а начатое доживает своё.
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
        })
}
