//! Команды терминала: `socks`, `http`, `rules`, `profiles`, `doctor`.
//!
//! Работают сами по себе — без службы, прав и драйвера. Библиотека: роль
//! выбирает `crates/app`.

pub mod args;
pub mod commands;
pub mod output;

use anyhow::{Context, Result};
use args::Command;
use output::Format;
use penguin_config::{ConfigStore, Paths};

/// Выполняет команду терминала.
pub fn run(command: &Command, config_dir: Option<&std::path::Path>, json: bool) -> Result<()> {
    // Настройки не нужны, и битый файл не должен мешать обновиться.
    if let Command::Update(update) = command {
        return commands::update::run(update, Format::from_flag(json));
    }

    let store = match config_dir {
        Some(dir) => ConfigStore::new(Paths::rooted(dir)),
        None => ConfigStore::discover().context("не удалось определить каталог настроек")?,
    };

    let config = store.load().with_context(|| {
        format!(
            "не читаются настройки из {}",
            store.paths().config_file().display()
        )
    })?;

    let format = Format::from_flag(json);

    match command {
        Command::Socks(socks) => block_on(commands::socks::run(
            &config,
            socks,
            commands::socks::Kind::Socks5,
        )),
        Command::Http(http) => block_on(commands::socks::run(
            &config,
            http,
            commands::socks::Kind::Http,
        )),
        Command::Profiles(command) => commands::profiles::run(&config, command, format),
        Command::Rules(command) => commands::rules::run(&config, command, format),
        Command::Doctor => commands::doctor::run(&store, &config, format),
        Command::Update(update) => commands::update::run(update, format),
    }
}

/// Запускает асинхронную команду.
///
/// Среда выполнения создаётся только там, где она нужна: `rules` и `doctor`
/// работают без сети, и поднимать под них пул потоков незачем.
fn block_on<F: std::future::Future<Output = Result<()>>>(future: F) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("не удалось создать среду выполнения")?
        .block_on(future)
}
