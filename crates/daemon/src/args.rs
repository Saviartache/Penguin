//! Аргументы запуска: как служба, как обычный процесс, установка и удаление.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Служба Penguin.
#[derive(Debug, Parser)]
#[command(name = "penguin-daemon", version, about, long_about = None)]
pub struct Cli {
    /// Каталог с настройками.
    #[arg(long, global = true, value_name = "ПУТЬ")]
    pub config_dir: Option<PathBuf>,

    /// Запущено диспетчером служб.
    ///
    /// Флаг ставит сама система при установке службы; вручную его писать не
    /// нужно и бессмысленно — вне диспетчера запуск с ним не удастся.
    #[arg(long, hide = true)]
    pub service: bool,

    /// Подробный вывод.
    #[arg(short, long)]
    pub verbose: bool,

    /// Что сделать со службой. Без команды — запустить демона.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Команды управления службой.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Поставить службу.
    Install,
    /// Убрать службу.
    Uninstall,
    /// Запустить службу.
    Start,
    /// Остановить службу.
    Stop,
    /// Показать состояние службы и диагностику.
    Status,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn no_command_means_run_the_daemon() {
        let cli = Cli::try_parse_from(["penguin-daemon"]).expect("разбирается");
        assert!(cli.command.is_none());
        assert!(!cli.service);
    }

    #[test]
    fn service_flag_is_recognised() {
        // Флаг ставит диспетчер служб при запуске; путь запуска у демона от
        // него другой.
        let cli = Cli::try_parse_from(["penguin-daemon", "--service"]).expect("разбирается");
        assert!(cli.service);
    }

    #[test]
    fn service_commands_parse() {
        for (args, matches) in [
            (
                ["penguin-daemon", "install"],
                matches!(Command::Install, Command::Install),
            ),
            (
                ["penguin-daemon", "stop"],
                matches!(Command::Stop, Command::Stop),
            ),
        ] {
            let cli = Cli::try_parse_from(args).expect("разбирается");
            assert!(cli.command.is_some());
            assert!(matches);
        }
    }

    #[test]
    fn config_dir_is_accepted() {
        let cli = Cli::try_parse_from(["penguin-daemon", "--config-dir", "C:/penguin"])
            .expect("разбирается");
        assert_eq!(cli.config_dir, Some(PathBuf::from("C:/penguin")));
    }
}
