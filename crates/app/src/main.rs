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

use anyhow::{Context, Result};
use args::{Cli, Command, ServiceCommand};
use clap::Parser;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // До первой печати: подключаться к консоли родителя надо раньше, чем в неё
    // что-то пойдёт.
    if cli.writes_to_console() {
        console::attach_to_parent();
    }

    // Права спрашиваются один раз и заранее — до того, как команда начнёт
    // работать и упрётся в отказ на середине.
    if cli.needs_elevation() && !penguin_platform::is_elevated() {
        return elevate_and_exit(&cli);
    }

    let _guard = logging::init(&cli);

    match &cli.command {
        // --- служба ---
        Some(Command::Service(command)) => service(command),

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

/// Выполняет команду службы.
fn service(command: &ServiceCommand) -> Result<()> {
    match command {
        ServiceCommand::Ensure => ensure(),
        ServiceCommand::Install => penguin_daemon::install(),
        ServiceCommand::Uninstall => penguin_daemon::uninstall(),
        ServiceCommand::Restart => restart(),
        ServiceCommand::Start => {
            penguin_platform::service::start().context("не удалось запустить службу")
        }
        ServiceCommand::Stop => {
            penguin_platform::service::stop().context("не удалось остановить службу")
        }
        ServiceCommand::Status => penguin_daemon::status(),
    }
}

/// Доводит службу до рабочего состояния: ставит, если её нет, и запускает.
///
/// Ровно то, что нужно окну: оно не знает и не хочет знать, установлена служба
/// или только остановлена, — ему нужно, чтобы она работала. Поэтому одна
/// команда, а не две: два запроса UAC подряд ради одного действия — плохая
/// цена за аккуратность API.
fn ensure() -> Result<()> {
    use penguin_platform::service::ServiceStatus;

    let mut status = penguin_platform::service::status().context("не удалось узнать состояние")?;

    // Установленной службы мало: она может быть зарегистрирована на другой
    // файл — прошлую сборку, копию в другом каталоге. Тогда тоннель поднимает
    // не та программа, которую запустил человек, и рядом с ней может не
    // оказаться ни драйвера, ни настроек. Снаружи это выглядит как «поставил
    // новую версию, а ошибки те же».
    if status != ServiceStatus::NotInstalled
        && !penguin_platform::service::matches_current_executable()
    {
        println!("Служба указывает на другой файл — переустанавливаю.");
        penguin_daemon::uninstall()?;
        status = ServiceStatus::NotInstalled;
    }

    if status == ServiceStatus::NotInstalled {
        penguin_daemon::install()?;
        // Свежепоставленная служба не работает — её ещё предстоит запустить.
        status = ServiceStatus::Stopped;
    }

    // «Числится работающей» — ещё не «работает». Демон, зависший с поднятым
    // тоннелем, для диспетчера жив, а на запросы не отвечает: окно ждёт ответа,
    // которого не будет, и снять тоннель некому. Такую службу поднимаем заново,
    // и это единственное, что тут помогает.
    if status == ServiceStatus::Running && !penguin_daemon::responds() {
        println!("Служба не отвечает — перезапускаю.");
        return restart();
    }

    // Уже работающую службу запускать не надо: команда вернула бы отказ, а
    // делать при этом ничего не требуется.
    if status != ServiceStatus::Running {
        penguin_platform::service::start().context("не удалось запустить службу")?;
    }
    println!("Служба работает.");
    Ok(())
}

/// Перезапускает службу.
///
/// Нужна после замены файла: служба держит в памяти тот образ, с которым её
/// запустили, и положенное рядом исправление не действует, пока она не
/// поднялась заново.
fn restart() -> Result<()> {
    // Остановка может не удаться потому, что служба и так стоит; это не
    // причина не запускать её.
    if let Err(err) = penguin_platform::service::stop() {
        tracing::debug!(%err, "останавливать было нечего");
    }
    penguin_platform::service::start().context("не удалось запустить службу")?;
    println!("Служба перезапущена.");
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
}
