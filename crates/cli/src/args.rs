//! Разбор команд.

use std::net::SocketAddr;

use clap::Subcommand;

/// Команды клиента.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Локальный SOCKS5 поверх выбранного профиля.
    ///
    /// Не требует ни прав администратора, ни драйвера: приложение
    /// настраивается на указанный адрес, и его трафик идёт через тоннель.
    Socks(SocksArgs),

    /// Локальный HTTP-прокси поверх выбранного профиля.
    Http(SocksArgs),

    /// Профили: список и проверка.
    #[command(subcommand)]
    Profiles(ProfilesCommand),

    /// Правила маршрутизации.
    #[command(subcommand)]
    Rules(RulesCommand),

    /// Проверка окружения: настройки, профили, права.
    Doctor,
}

/// Параметры локального прокси.
#[derive(Debug, clap::Args)]
pub struct SocksArgs {
    /// Профиль. По умолчанию — активный из настроек.
    #[arg(short, long, value_name = "ИМЯ")]
    pub profile: Option<String>,

    /// Где слушать.
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    pub listen: SocketAddr,

    /// Не применять правила: весь трафик в тоннель.
    ///
    /// Нужно, когда надо проверить именно протокол, отделив его от
    /// маршрутизации.
    #[arg(long)]
    pub no_rules: bool,
}

/// Команды профилей.
#[derive(Debug, Subcommand)]
pub enum ProfilesCommand {
    /// Список профилей.
    List,
    /// Проверить настройки профиля, не подключаясь.
    Check {
        /// Профиль. По умолчанию — все.
        #[arg(value_name = "ИМЯ")]
        profile: Option<String>,
    },
}

/// Команды правил.
#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// Список правил в порядке разбора.
    List,

    /// Объяснить, что случится с таким соединением.
    ///
    /// Отвечает на главный вопрос пользователя: «почему это приложение
    /// пошло не туда».
    Explain {
        /// Куда: `example.com:443` или `1.2.3.4:443`.
        #[arg(value_name = "АДРЕС")]
        destination: String,

        /// Путь к приложению или имя исполняемого файла.
        #[arg(short, long, value_name = "ПУТЬ")]
        process: Option<String>,

        /// Считать соединение UDP, а не TCP.
        #[arg(long)]
        udp: bool,
    },
}
