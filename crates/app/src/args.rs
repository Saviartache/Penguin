//! Аргументы: кем программе быть в этот раз.
//!
//! Файл один, ролей три, и выбирает роль он сам:
//!
//! | Запуск | Роль |
//! |---|---|
//! | двойной щелчок, `penguin` | окно |
//! | `penguin doctor`, `penguin socks`, … | терминал |
//! | `penguin service …` | управление службой |
//! | `penguin --service` | служба, запущенная диспетчером |
//! | `penguin --foreground` | служба на переднем плане, для отладки |
//!
//! Роль по умолчанию — окно, и это не мелочь: программу запускают двойным
//! щелчком, а не из терминала, и «без аргументов» для неё должно означать
//! «покажи окно», а не «напечатай справку».

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Penguin: VPN-клиент с раздельным тоннелированием.
#[derive(Debug, Parser)]
#[command(name = "penguin", version, about, long_about = None)]
pub struct Cli {
    /// Каталог с настройками. По умолчанию — общий, а до установки службы
    /// каталог пользователя.
    #[arg(long, global = true, value_name = "ПУТЬ")]
    pub config_dir: Option<PathBuf>,

    /// Desktop identity approved by the elevated service helper (Unix only).
    #[arg(long, global = true, hide = true)]
    pub controller_uid: Option<u32>,

    /// Pre-elevation configuration source; only imported on first installation.
    #[arg(long, global = true, hide = true)]
    pub import_config: Option<PathBuf>,

    /// Подробный вывод в журнал.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Вывод в JSON — для скриптов.
    #[arg(long, global = true)]
    pub json: bool,

    /// Запущено диспетчером служб.
    ///
    /// Флаг ставит система при установке службы; вручную его писать не нужно и
    /// бессмысленно — вне диспетчера запуск с ним не удастся.
    #[arg(long, hide = true)]
    pub service: bool,

    /// Держать службу на переднем плане — так её запускают при отладке.
    #[arg(long, hide = true)]
    pub foreground: bool,

    /// Что делать. Без команды — открыть окно.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Команды программы.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Команды терминала: проверка, локальный прокси, правила, профили.
    ///
    /// Плоско, а не отдельной группой: `penguin doctor` короче и привычнее,
    /// чем `penguin cli doctor`, а никакой другой `doctor` в программе нет.
    #[command(flatten)]
    Client(penguin_cli::args::Command),

    /// Служба: установка, запуск, состояние.
    #[command(subcommand)]
    Service(ServiceCommand),
}

/// Что сделать со службой.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum ServiceCommand {
    /// Поставить службу и запустить её — одной командой.
    ///
    /// То, что нужно окну: оно не знает и не хочет знать, установлена служба
    /// или только остановлена, — ему нужно, чтобы она работала. Повторный
    /// вызов ничего не ломает.
    Ensure,
    /// Поставить службу.
    Install,
    /// Убрать службу.
    Uninstall,
    /// Перезапустить службу.
    ///
    /// Нужна после замены файла: служба держит в памяти тот образ, с которым
    /// её запустили, и новый код не действует, пока она не поднялась заново.
    Restart,
    /// Запустить службу.
    Start,
    /// Остановить службу.
    Stop,
    /// Показать состояние службы и диагностику.
    Status,
}

impl Cli {
    /// Нужны ли этому запуску права администратора.
    ///
    /// Свободная функция с тестом: список ролей, требующих прав, — это то, что
    /// решает, показывать ли запрос UAC. Ошибиться в нём означает либо
    /// спрашивать права там, где они не нужны, либо не спросить там, где нужны.
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

    /// Печатает ли этот запуск что-то в терминал.
    ///
    /// От этого зависит, подключаться ли к консоли родителя: программа собрана
    /// как оконная, и без подключения её вывод не виден нигде.
    pub fn writes_to_console(&self) -> bool {
        // Окно и служба не печатают: у первого консоли нет, у второй — тем
        // более. Всё остальное — печатает.
        self.command.is_some() || self.foreground
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;
    use penguin_cli::args::{Command as ClientCommand, RulesCommand};

    use super::*;

    #[test]
    fn the_command_tree_is_valid() {
        // `debug_assert` внутри clap ловит противоречия в объявлении: два
        // одинаковых коротких флага, обязательный аргумент после
        // необязательного и тому подобное.
        Cli::command().debug_assert();
    }

    #[test]
    fn no_arguments_means_the_window() {
        // Программу запускают двойным щелчком: «без аргументов» обязано
        // означать «покажи окно», а не «напечатай справку».
        let cli = Cli::try_parse_from(["penguin"]).expect("разбирается");
        assert!(cli.command.is_none());
        assert!(!cli.service);
    }

    #[test]
    fn terminal_commands_stay_flat() {
        // `penguin doctor`, а не `penguin cli doctor`.
        let cli = Cli::try_parse_from(["penguin", "doctor"]).expect("разбирается");
        assert!(matches!(
            cli.command,
            Some(Command::Client(ClientCommand::Doctor))
        ));
    }

    #[test]
    fn socks_keeps_its_loopback_default() {
        let cli = Cli::try_parse_from(["penguin", "socks"]).expect("разбирается");
        let Some(Command::Client(ClientCommand::Socks(args))) = cli.command else {
            panic!("не та команда")
        };
        // Только петля: прокси, открытый наружу, — открытый прокси для всей
        // сети.
        assert!(args.listen.ip().is_loopback());
        assert_eq!(args.listen.port(), 1080);
    }

    #[test]
    fn explain_takes_a_process_and_a_destination() {
        let cli = Cli::try_parse_from([
            "penguin",
            "rules",
            "explain",
            "example.com:443",
            "--process",
            "chrome.exe",
        ])
        .expect("разбирается");

        let Some(Command::Client(ClientCommand::Rules(RulesCommand::Explain {
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
    fn global_flags_work_after_the_subcommand() {
        // Пользователь пишет флаг там, где вспомнил о нём.
        let cli = Cli::try_parse_from(["penguin", "doctor", "--json"]).expect("разбирается");
        assert!(cli.json);
    }

    #[test]
    fn the_service_dispatcher_flag_is_recognised() {
        let cli = Cli::try_parse_from(["penguin", "--service"]).expect("разбирается");
        assert!(cli.service);
        assert!(cli.command.is_none());
    }

    #[test]
    fn only_service_commands_ask_for_rights() {
        // Спросить права там, где они не нужны, — лишний запрос UAC на ровном
        // месте; не спросить там, где нужны, — команда, падающая с отказом.
        for args in [
            vec!["penguin", "service", "ensure"],
            vec!["penguin", "service", "install"],
            vec!["penguin", "service", "start"],
            vec!["penguin", "service", "stop"],
            vec!["penguin", "service", "uninstall"],
            vec!["penguin", "service", "restart"],
        ] {
            let cli = Cli::try_parse_from(&args).expect("разбирается");
            assert!(cli.needs_elevation(), "{args:?} обязана просить права");
        }

        for args in [
            vec!["penguin"],
            vec!["penguin", "doctor"],
            vec!["penguin", "socks"],
            vec!["penguin", "service", "status"],
        ] {
            let cli = Cli::try_parse_from(&args).expect("разбирается");
            assert!(!cli.needs_elevation(), "{args:?} права не нужны");
        }
    }

    #[test]
    fn only_terminal_roles_print() {
        // Программа собрана как оконная: без подключения к консоли родителя её
        // вывод не виден нигде.
        assert!(
            !Cli::try_parse_from(["penguin"])
                .expect("р")
                .writes_to_console()
        );
        assert!(
            !Cli::try_parse_from(["penguin", "--service"])
                .expect("р")
                .writes_to_console()
        );
        assert!(
            Cli::try_parse_from(["penguin", "doctor"])
                .expect("р")
                .writes_to_console()
        );
        assert!(
            Cli::try_parse_from(["penguin", "--foreground"])
                .expect("р")
                .writes_to_console()
        );
    }
}
