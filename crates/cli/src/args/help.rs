//! Тексты справки команд терминала.

/// Общие флаги, которые разбирает исполняемый файл.
macro_rules! global_options {
    () => {
        "      --config-dir <ПУТЬ>  Каталог с настройками. По умолчанию — общий, а до установки службы каталог пользователя
  -v, --verbose            Подробный вывод в журнал
      --json               Вывод в JSON — для скриптов
  -h, --help               Справка
"
    };
}

pub(super) const SOCKS: &str = concat!(
    "Локальный SOCKS5 поверх выбранного профиля.

Не требует ни прав администратора, ни драйвера: приложение настраивается на указанный адрес, и его трафик идёт через тоннель.

Usage: penguin socks [OPTIONS]

Options:
  -p, --profile <ИМЯ>      Профиль. По умолчанию — активный из настроек
  -l, --listen <LISTEN>    Где слушать [default: 127.0.0.1:1080]
      --no-rules           Не применять правила: весь трафик в тоннель
",
    global_options!()
);

pub(super) const HTTP: &str = concat!(
    "Локальный HTTP-прокси поверх выбранного профиля

Usage: penguin http [OPTIONS]

Options:
  -p, --profile <ИМЯ>      Профиль. По умолчанию — активный из настроек
  -l, --listen <LISTEN>    Где слушать [default: 127.0.0.1:1080]
      --no-rules           Не применять правила: весь трафик в тоннель
",
    global_options!()
);

pub(super) const PROFILES: &str = concat!(
    "Профили: список и проверка

Usage: penguin profiles [OPTIONS] <COMMAND>

Commands:
  list   Список профилей
  check  Проверить настройки профиля, не подключаясь

Options:
",
    global_options!()
);

pub(super) const PROFILES_LIST: &str = concat!(
    "Список профилей

Usage: penguin profiles list [OPTIONS]

Options:
",
    global_options!()
);

pub(super) const PROFILES_CHECK: &str = concat!(
    "Проверить настройки профиля, не подключаясь

Usage: penguin profiles check [OPTIONS] [ИМЯ]

Arguments:
  [ИМЯ]  Профиль. По умолчанию — все

Options:
",
    global_options!()
);

pub(super) const RULES: &str = concat!(
    "Правила маршрутизации

Usage: penguin rules [OPTIONS] <COMMAND>

Commands:
  list     Список правил в порядке разбора
  explain  Объяснить, что случится с таким соединением

Options:
",
    global_options!()
);

pub(super) const RULES_LIST: &str = concat!(
    "Список правил в порядке разбора

Usage: penguin rules list [OPTIONS]

Options:
",
    global_options!()
);

pub(super) const RULES_EXPLAIN: &str = concat!(
    "Объяснить, что случится с таким соединением.

Отвечает на главный вопрос пользователя: «почему это приложение пошло не туда».

Usage: penguin rules explain [OPTIONS] <АДРЕС>

Arguments:
  <АДРЕС>  Куда: `example.com:443` или `1.2.3.4:443`

Options:
  -p, --process <ПУТЬ>     Путь к приложению или имя исполняемого файла
      --udp                Считать соединение UDP, а не TCP
",
    global_options!()
);

pub(super) const DOCTOR: &str = concat!(
    "Проверка окружения: настройки, профили, права

Usage: penguin doctor [OPTIONS]

Options:
",
    global_options!()
);
