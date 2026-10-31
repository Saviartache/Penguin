//! Тексты справки верхнего уровня и службы.

/// Версия для `--version`.
pub const VERSION: &str = concat!("penguin ", env!("CARGO_PKG_VERSION"), "\n");

/// Общие флаги, которые разбирает исполняемый файл.
macro_rules! options {
    () => {
        "Options:
      --config-dir <ПУТЬ>  Каталог с настройками. По умолчанию — общий, а до установки службы каталог пользователя
  -v, --verbose            Подробный вывод в журнал
      --json               Вывод в JSON — для скриптов
"
    };
}

/// Справка одной команды службы.
macro_rules! service_command {
    ($name:literal, $about:literal) => {
        concat!(
            $about,
            "\n\nUsage: penguin service ",
            $name,
            " [OPTIONS]\n\n",
            options!(),
            "  -h, --help               Справка\n"
        )
    };
}

pub const TOP: &str = concat!(
    "Главный файл Penguin

Usage: penguin [OPTIONS] [COMMAND]

Commands:
  socks     Локальный SOCKS5 поверх выбранного профиля
  http      Локальный HTTP-прокси поверх выбранного профиля
  profiles  Профили: список и проверка
  rules     Правила маршрутизации
  doctor    Проверка окружения: настройки, профили, права
  update    Обновление с GitHub: проверка и установка
  geoip     Страна серверов по базе GeoIP
  deploy    Развернуть сервер Pingwin на своей машине по SSH
  service   Служба: установка, запуск, состояние
  help      Справка по команде

",
    options!(),
    "      --tray               Открыть окно свёрнутым в значок лотка (автозапуск)
  -h, --help               Справка
  -V, --version            Версия
"
);

pub const SERVICE: &str = concat!(
    "Служба: установка, запуск, состояние

Usage: penguin service [OPTIONS] <COMMAND>

Commands:
  ensure     Поставить службу и запустить её — одной командой
  install    Поставить службу
  uninstall  Убрать службу
  restart    Перезапустить службу
  start      Запустить службу
  stop       Остановить службу
  status     Показать состояние службы и диагностику

",
    options!(),
    "  -h, --help               Справка\n"
);

pub const ENSURE: &str = service_command!(
    "ensure",
    "Поставить службу и запустить её — одной командой.\n\nПовторный вызов ничего не ломает."
);
pub const INSTALL: &str = service_command!("install", "Поставить службу");
pub const UNINSTALL: &str = service_command!("uninstall", "Убрать службу");
pub const RESTART: &str = service_command!(
    "restart",
    "Перезапустить службу.\n\nНужна после замены файла: служба держит в памяти старый образ."
);
pub const START: &str = service_command!("start", "Запустить службу");
pub const STOP: &str = service_command!("stop", "Остановить службу");
pub const STATUS: &str = service_command!("status", "Показать состояние службы и диагностику");
