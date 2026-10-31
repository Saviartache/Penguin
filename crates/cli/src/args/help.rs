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

pub(super) const UPDATE: &str = concat!(
    "Обновление с GitHub

Usage: penguin update [OPTIONS] <COMMAND>

Commands:
  check    Спросить GitHub, есть ли выпуск новее
  install  Скачать выпуск, сверить SHA-256 и заменить исполняемый файл

Options:
",
    global_options!()
);

pub(super) const UPDATE_CHECK: &str = concat!(
    "Спросить GitHub, есть ли выпуск новее

Usage: penguin update check [OPTIONS]

Options:
",
    global_options!()
);

pub(super) const UPDATE_INSTALL: &str = concat!(
    "Скачать выпуск, сверить SHA-256 и заменить исполняемый файл.

Служба подхватит новую сборку при следующем запуске окна или командой `penguin service restart`.

Usage: penguin update install [OPTIONS]

Options:
",
    global_options!()
);

pub(super) const DEPLOY: &str = concat!(
    "Развернуть сервер на своей машине по SSH

Usage: penguin deploy [OPTIONS] <COMMAND>

Commands:
  pingwin  Сервер Pingwin в Docker: сборка, сертификат, ключи, ссылка

Options:
",
    global_options!()
);

pub(super) const DEPLOY_PINGWIN: &str = concat!(
    "Развернуть сервер Pingwin на машине Linux через системный ssh (OpenSSH 8.4+).

Запрос — JSON на stdin, не в аргументах: пароль не должен попасть в список
процессов. Поля: host, ssh_port [22], ssh_user [root], password или key_file
(без них — агент ssh), domain, port [443], email, user [client], profile.
Пользователю не root нужен sudo без пароля. Сервер собирается из исходников
той же версии, что у клиента; в конце печатается ссылка pingwin://.

Usage: penguin deploy pingwin [OPTIONS] < запрос.json

Options:
",
    global_options!()
);

pub(super) const GEOIP: &str = concat!(
    "Страна серверов по базе GeoIP.

База DB-IP Lite (IP Geolocation by DB-IP, CC BY 4.0) скачивается с GitHub в
каталог данных пользователя и обновляется раз в месяц. Имя сервера резолвится
системным резолвером; не найденные в выводе отсутствуют. Без серверов команда
только обновляет базу.

Usage: penguin geoip [OPTIONS] [СЕРВЕР]...

Arguments:
  [СЕРВЕР]...  Адрес `хост:порт` или просто хост

Options:
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

pub(super) const SUBSCRIPTION: &str = concat!(
    "Подписка Amnezia: сервы по ключу vpn://

Usage: penguin subscription [OPTIONS] <COMMAND>

Commands:
  refresh  Забрать серверы у шлюза и завести как управляемые профили
  list     Показать заведённые подписки
  remove   Убрать подписку и её профили

Options:
",
    global_options!()
);

pub(super) const SUBSCRIPTION_REFRESH: &str = concat!(
    "Забрать серверы подписки у шлюза и завести как управляемые профили.

Ключ подписки `vpn://…` — свой, из оплаченной подписки Amnezia. Устройство
(ключи и installation_uuid) хранится у настроек и переиспользуется, чтобы не
тратить слоты. Без ключа обновляет уже заведённые подписки.

О боевой шлюз (gw.amnezia.org) проверяется пользователем: по умолчанию берётся
один из двух извлечённых ключей шлюза, боевой из них не подтверждён.

Usage: penguin subscription refresh [OPTIONS] [КЛЮЧ]

Arguments:
  [КЛЮЧ]  Ключ подписки `vpn://…`. По умолчанию — обновить все заведённые

Options:
      --id <ID>            Обновить только одну заведённую подписку по идентификатору
      --connect-event      Пометить запрос событием подключения (шлюз держит пир живым)
      --dev                Взять второй (dev) ключ шлюза — если первый даёт 500
      --endpoint <URL>     Адрес шлюза вместо боевого (отладка, dev-шлюз)
      --country <КОД>      Обновить только одну локацию (иначе — все)
",
    global_options!()
);

pub(super) const SUBSCRIPTION_LIST: &str = concat!(
    "Показать заведённые подписки

Usage: penguin subscription list [OPTIONS]

Options:
",
    global_options!()
);

pub(super) const SUBSCRIPTION_REMOVE: &str = concat!(
    "Убрать подписку и все её профили

Usage: penguin subscription remove [OPTIONS] <ID>

Arguments:
  <ID>  Идентификатор подписки (из `subscription list`)

Options:
",
    global_options!()
);
