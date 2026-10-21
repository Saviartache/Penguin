//! Локализация: все подписи в одной структуре [`Strings`], язык — её значение
//! ([`ru::STRINGS`], [`en::STRINGS`]); пропущенный перевод не собирается.
//!
//! Язык выбирается один раз до первой отрисовки и на ходу не меняется.

pub mod en;
pub mod ru;

use std::sync::OnceLock;

use penguin_config::schema::app::Language;
use penguin_config::schema::routing::TunnelMode;

/// Все подписи окна.
#[derive(Debug, Clone, Copy)]
pub struct Strings {
    // --- вкладки ---
    /// Подписи вкладок в порядке [`crate::app::Screen::ALL`].
    pub screens: [&'static str; 4],

    // --- компактное окно ---
    /// Заголовок панели с текущей конфигурацией.
    pub configuration: &'static str,
    /// Профиль.
    pub profile: &'static str,
    /// Сервер.
    pub server: &'static str,
    /// Протокол.
    pub protocol: &'static str,
    /// Задержка до сервера.
    pub latency: &'static str,
    /// Состояние тоннеля — строкой консоли.
    pub status: &'static str,

    /// Раздел трафика.
    pub traffic: &'static str,
    /// Раздел списка правил.
    pub rules: &'static str,
    /// Раздел событий журнала.
    pub events: &'static str,

    // --- состояние тоннеля ---
    /// Тоннель работает.
    pub connected: &'static str,
    /// Тоннель поднимается.
    pub connecting: &'static str,
    /// Соединение потеряно, идёт переподключение.
    pub reconnecting: &'static str,
    /// Тоннель опускается.
    pub disconnecting: &'static str,
    /// Тоннель выключен.
    pub disconnected: &'static str,
    /// Демон не отвечает.
    pub daemon_offline: &'static str,
    /// Службу гасят вместе с окном.
    pub daemon_stopping: &'static str,
    /// Служба поднимается.
    pub service_starting: &'static str,
    /// Прав не дали.
    pub service_needs_rights: &'static str,
    /// Служба поставлена, но на связь не вышла.
    pub service_silent: &'static str,
    /// Служба пропала после того, как права уже давали.
    pub service_lost: &'static str,
    /// Служба останавливается вместе с окном.
    pub service_stopping: &'static str,

    // --- действия ---
    /// Запустить службу, которая не отвечает.
    pub start_service: &'static str,
    /// Включить тоннель.
    pub connect: &'static str,
    /// Выключить тоннель.
    pub disconnect: &'static str,
    /// Сохранить изменения.
    pub save: &'static str,
    /// Проверить.
    pub probe: &'static str,
    /// Остановить идущую проверку.
    pub probe_stop: &'static str,
    /// Проверить один сервер — действие в строке.
    pub ping: &'static str,
    /// Удалить.
    pub remove: &'static str,
    /// Как выбрать профиль — подсказкой у нижнего края списка.
    pub select_hint: &'static str,
    /// Править.
    pub edit: &'static str,
    /// Поиск по таблице — подсказкой внутри поля.
    pub search: &'static str,

    // --- главный экран ---
    /// Отдано.
    pub uploaded: &'static str,
    /// Принято.
    pub downloaded: &'static str,
    /// Соединений открыто.
    pub connections: &'static str,

    // --- серверы ---
    /// Профилей нет.
    pub no_profiles: &'static str,
    /// Не ответил.
    pub no_answer: &'static str,
    /// Идёт проверка.
    pub probing: &'static str,
    /// Единицы задержки.
    pub millis: &'static str,
    /// Профиль приехал из подписки.
    pub managed: &'static str,
    /// Добавить сервер.
    pub add_server: &'static str,
    /// Заголовок окна выбора протокола.
    pub choose_protocol: &'static str,
    /// Подпись раздела подписки в окне выбора.
    pub subscription: &'static str,
    /// Подсказка в поле ключа подписки.
    pub subscription_key_hint: &'static str,
    /// Кнопка «обновить по подписке».
    pub subscription_refresh: &'static str,
    /// Журнал: подписка обновлена (дальше число серверов).
    pub subscription_updated: &'static str,
    /// Журнал: подписка не обновлена (дальше причина).
    pub subscription_failed: &'static str,
    /// Журнал: страны серверов не определены (дальше причина).
    pub countries_failed: &'static str,
    /// Заголовок окна «как добавить WireGuard».
    pub wireguard_add: &'static str,
    /// Добавить WireGuard вручную (форма).
    pub wireguard_manual: &'static str,
    /// Добавить WireGuard из файла `.conf`.
    pub wireguard_from_conf: &'static str,
    /// Заголовок окна выбора файла `.conf`.
    pub import_conf_title: &'static str,
    /// Подпись вида файла `.conf` в окне выбора.
    pub wireguard_configs: &'static str,
    /// Журнал: файл `.conf` не разобран (дальше причина).
    pub import_conf_failed: &'static str,
    /// Протокол профиля этой сборке неизвестен.
    pub protocol_unknown: &'static str,
    /// Новый сервер.
    pub new_server: &'static str,
    /// Правка сервера.
    pub edit_server: &'static str,
    /// Имя профиля.
    pub server_name: &'static str,
    /// Адрес сервера.
    pub server_address: &'static str,
    /// Пример адреса — подсказкой внутри поля.
    pub server_address_example: &'static str,
    /// Пример полосы приёма.
    pub bandwidth_down_example: &'static str,
    /// Пример полосы отдачи.
    pub bandwidth_up_example: &'static str,
    /// Что вписать в поле имени TLS.
    pub sni_example: &'static str,
    /// Что вписать в поле обфускации.
    pub obfs_example: &'static str,
    /// Пароль.
    pub password: &'static str,
    /// Имя пользователя.
    pub username: &'static str,
    /// Адрес прокси.
    pub proxy_address: &'static str,
    /// Пример адреса прокси SOCKS5.
    pub socks_address_example: &'static str,
    /// Поле можно не заполнять — подсказкой внутри него.
    pub optional_hint: &'static str,
    /// Пускать ли UDP через прокси.
    pub proxy_udp: &'static str,
    /// То же под TLS: датаграммы в него не заворачиваются, DNS уходит открыто.
    pub proxy_udp_plain: &'static str,
    /// Имя для TLS.
    pub sni: &'static str,
    /// Чем переносится поток: голый TCP, gRPC, XHTTP.
    pub transport: &'static str,
    /// Метод шифрования.
    pub method: &'static str,
    /// UUID пользователя.
    pub uuid: &'static str,
    /// Чем шифруется соединение до сервера.
    pub security: &'static str,
    /// Управление перегрузкой у QUIC.
    pub congestion: &'static str,
    /// Чем едут датаграммы.
    pub udp_mode: &'static str,
    /// Не задан UUID.
    pub need_uuid: &'static str,
    /// Значение не разбирается как UUID.
    pub bad_uuid: &'static str,
    /// В ссылке нет UUID.
    pub link_no_uuid: &'static str,
    /// Не задан метод шифрования.
    pub need_method: &'static str,
    /// Путь запроса у переносов поверх HTTP.
    pub path: &'static str,
    /// Пример пути.
    pub path_example: &'static str,
    /// Заголовок `Host` у них же.
    pub http_host: &'static str,
    /// Пароль обфускации.
    pub obfs: &'static str,
    /// Не задано имя пользователя.
    pub need_username: &'static str,
    /// Отдача.
    pub bandwidth_up: &'static str,
    /// Приём.
    pub bandwidth_down: &'static str,
    /// Не проверять сертификат.
    pub insecure: &'static str,
    /// Отпечаток цепочки сертификатов.
    pub chain_fingerprint: &'static str,
    /// Что вписать в поле отпечатка цепочки.
    pub chain_fingerprint_example: &'static str,
    /// Приватный ключ.
    pub private_key: &'static str,
    /// Не задан приватный ключ.
    pub need_private_key: &'static str,
    /// Публичный ключ сервера.
    pub server_public_key: &'static str,
    /// Не задан публичный ключ сервера.
    pub need_server_public_key: &'static str,
    /// Предварительный ключ.
    pub preshared_key: &'static str,
    /// Адрес интерфейса внутри тоннеля.
    pub interface_address: &'static str,
    /// Что вписать в адрес интерфейса.
    pub interface_address_example: &'static str,
    /// Не задан адрес интерфейса.
    pub need_interface_address: &'static str,
    /// Адрес IPv6 интерфейса.
    pub interface_address_v6: &'static str,
    /// Серверы имён внутри тоннеля.
    pub tunnel_dns: &'static str,
    /// Что вписать в серверы имён.
    pub tunnel_dns_example: &'static str,
    /// Наибольший размер пакета.
    pub mtu: &'static str,
    /// Что вписать в MTU.
    pub mtu_example: &'static str,
    /// Как часто напоминать о себе.
    pub keepalive: &'static str,
    /// Что вписать в интервал.
    pub keepalive_example: &'static str,
    /// Учётные данные для заголовка `Authorization`.
    pub authorization: &'static str,
    /// Предупреждение: через MASQUE ходит только UDP.
    pub masque_udp_only: &'static str,
    /// Предупреждение: у MASQUE `CONNECT-IP` нет сервера имён внутри тоннеля.
    pub masque_ip_no_dns: &'static str,
    /// Предупреждение: VLESS + Reality не проверен о живой сервер.
    pub reality_unverified: &'static str,
    /// Что вписать в публичный ключ Reality.
    pub reality_public_key_example: &'static str,
    /// Короткий идентификатор Reality.
    pub reality_short_id: &'static str,
    /// Что вписать в короткий идентификатор Reality.
    pub reality_short_id_example: &'static str,
    /// Имя сайта, за который выдаёт себя сервер Reality.
    pub reality_server_name: &'static str,
    /// Что вписать в имя сайта Reality.
    pub reality_server_name_example: &'static str,
    /// Подпись поля `flow` у VLESS.
    pub flow: &'static str,
    /// Что вписать в поле `flow`.
    pub flow_example: &'static str,
    /// Что вписать в ключ сервера Pingwin.
    pub pingwin_key_example: &'static str,
    /// Способ обхода DPI в первой посылке.
    pub desync_strategy: &'static str,
    /// Не задан адрес.
    pub need_server: &'static str,
    /// Не задан пароль.
    pub need_password: &'static str,
    /// Адрес не разбирается.
    pub bad_server: &'static str,
    /// Поле для вставки ссылки-приглашения.
    pub link: &'static str,
    /// Что вписать в поле ссылки.
    pub link_example: &'static str,
    /// Строка не похожа на ссылку-приглашение.
    pub link_not_a_link: &'static str,
    /// В ссылке нет адреса.
    pub link_no_host: &'static str,
    /// Адрес в ссылке не разбирается.
    pub link_bad_host: &'static str,
    /// В ссылке нет пароля.
    pub link_no_password: &'static str,
    /// В ссылке перенос, которого клиент не говорит.
    pub link_unsupported_transport: &'static str,
    /// Идентичность пользователя VMess: UUID или произвольный текст.
    pub vmess_id: &'static str,
    /// Не задана идентичность VMess.
    pub need_vmess_id: &'static str,
    /// `alterId` — имя протокола, не переводится.
    pub alter_id: &'static str,
    /// Значение `alterId` не число.
    pub bad_alter_id: &'static str,
    /// Предупреждение: шифр `zero` отключает шифрование и заверение данных.
    pub vmess_zero_warning: &'static str,

    // --- правила ---
    /// Куда идёт всё остальное — полем сводки.
    pub mode: &'static str,
    /// Последняя строка списка: всё, что не подошло ни под одну группу.
    pub rest: &'static str,
    /// Что значит последняя строка.
    pub rest_hint: &'static str,
    /// Правил нет.
    pub no_rules: &'static str,
    /// Заголовок столбца с именем правила.
    pub rule: &'static str,
    /// Заголовок столбца с условием.
    pub condition: &'static str,
    /// Заголовок столбца с действием.
    pub action: &'static str,
    /// Правило выключено — меткой в строке.
    pub rule_off: &'static str,
    /// Как включить или выключить правило — подсказкой у нижнего края таблицы.
    pub toggle_hint: &'static str,
    /// Проверить правило — кнопкой над таблицей.
    pub probe_rule: &'static str,
    /// Проверка правил.
    pub rule_probe: &'static str,
    /// Что покажет проверка — строкой на месте ещё не полученного ответа.
    pub probe_hint: &'static str,
    /// Куда.
    pub destination: &'static str,
    /// Какое приложение.
    pub process: &'static str,
    /// Имя правила.
    pub rule_name: &'static str,
    /// Раздел приложений в окне группы.
    pub apps_section: &'static str,
    /// Раздел сайтов и адресов.
    pub hosts_section: &'static str,
    /// Что можно вписать в строку адресов.
    pub hosts_hint: &'static str,
    /// Раздел портов.
    pub ports_section: &'static str,
    /// Что можно вписать в строку портов.
    pub ports_hint: &'static str,
    /// Пустой раздел не сужает группу.
    pub empty_means_any: &'static str,
    /// Разделы группы значат «и».
    pub sections_hint: &'static str,
    /// Пометка `=домен` в списке адресов.
    pub host_exact: &'static str,
    /// Пометка `*слово*` в списке адресов.
    pub host_keyword: &'static str,
    /// В разделе адресов или портов пусто.
    pub values_empty: &'static str,
    /// Набранного в разделе нет.
    pub values_not_found: &'static str,
    /// Добавить правило.
    pub add_rule: &'static str,
    /// Новое правило.
    pub new_rule: &'static str,
    /// Заголовок окна правки группы.
    pub edit_rule: &'static str,
    /// Имя правила, которое не назвали.
    pub unnamed_rule: &'static str,
    /// Действие «мимо тоннеля».
    pub action_direct: &'static str,
    /// Действие «через тоннель».
    pub action_tunnel: &'static str,
    /// Действие «оборвать».
    pub action_block: &'static str,
    /// Поиск по приложениям.
    pub app_search: &'static str,
    /// Список приложений пуст.
    pub no_apps: &'static str,
    /// Поиск ничего не нашёл.
    pub nothing_found: &'static str,
    /// Показать программу файлом — кнопкой рядом с поиском.
    pub pick_app: &'static str,
    /// Заголовок системного окна выбора файла.
    pub pick_app_title: &'static str,
    /// Как назван вид исполняемых файлов в окне выбора.
    pub programs: &'static str,
    /// Окно выбора файла не открылось.
    pub pick_failed: &'static str,
    /// Кнопка импорта списка правил.
    pub import_rules: &'static str,
    /// Заголовок окна выбора списка правил.
    pub import_title: &'static str,
    /// Как назван вид файлов со списками правил.
    pub rule_lists: &'static str,
    /// Файл списка не прочитался.
    pub import_failed: &'static str,
    /// В списке нет ничего, что набор выразит.
    pub import_empty: &'static str,
    /// Сколько групп добавлено.
    pub imported_groups: &'static str,
    /// Сколько строк пропущено.
    pub skipped_lines: &'static str,
    /// Кнопка выгрузки списка правил.
    pub export_rules: &'static str,
    /// Заголовок окна сохранения списка правил.
    pub export_title: &'static str,
    /// Файл списка не записался.
    pub export_failed: &'static str,
    /// Сколько групп выгружено.
    pub exported_groups: &'static str,
    /// Сколько групп Surge выразил не целиком.
    pub skipped_groups: &'static str,
    /// Плашка журнала: что делают кнопки мыши.
    pub log_hint: &'static str,
    /// Плашка после копирования.
    pub copied: &'static str,
    /// Плашка отмотанного журнала: вернуться к новым строкам.
    pub to_tail: &'static str,
    /// Заголовок окна правила по соединению.
    pub flow_rule: &'static str,
    /// Перед нынешним решением.
    pub decided_now: &'static str,
    /// Ловить адрес.
    pub catch_address: &'static str,
    /// Ловить приложение.
    pub catch_app: &'static str,
    /// Путь приложения служба не прислала.
    pub path_unknown: &'static str,
    /// Раздел «в какую группу».
    pub into_group: &'static str,
    /// Пункт новой группы.
    pub new_group: &'static str,
    /// Кнопка окна правила.
    pub add: &'static str,
    /// Строка журнала после добавления.
    pub added_to_group: &'static str,

    // --- журнал ---
    /// Метка ошибки.
    pub level_error: &'static str,
    /// Метка предупреждения.
    pub level_warning: &'static str,

    // --- настройки ---
    /// Переключатель включён — значением у правого края строки.
    pub on: &'static str,
    /// Переключатель выключен.
    pub off: &'static str,
    /// Раздел запуска.
    pub startup: &'static str,
    /// Раздел сети.
    pub network: &'static str,
    /// Раздел журнала.
    pub log: &'static str,
    /// Запускать при входе в систему.
    pub autostart: &'static str,
    /// Подключаться при запуске.
    pub autoconnect: &'static str,
    /// Kill switch.
    pub kill_switch: &'static str,
    /// Локальная сеть мимо тоннеля.
    pub allow_lan: &'static str,
    /// Забирать маршрут по умолчанию.
    pub capture_default_route: &'static str,
    /// Перехват запросов имён.
    pub dns_hijack: &'static str,
    /// Подробность журнала службы.
    pub verbose_log: &'static str,

    // --- обновления ---
    /// Раздел обновлений.
    pub updates: &'static str,
    /// Проверять обновления при запуске.
    pub check_updates: &'static str,
    /// «Версия» в строке «Версия 0.7.2, доступна 0.8.0».
    pub version: &'static str,
    /// «доступна» в той же строке.
    pub update_available: &'static str,
    /// Установлена последняя.
    pub update_latest: &'static str,
    /// Идёт проверка.
    pub update_checking: &'static str,
    /// Идёт установка.
    pub update_installing: &'static str,
    /// Установлено, окно перезапускается.
    pub update_restarting: &'static str,
    /// Начало строки с причиной отказа.
    pub update_failed: &'static str,
    /// Кнопка проверки.
    pub update_check: &'static str,
    /// Кнопка установки.
    pub update_install: &'static str,
    /// Поле компактного окна.
    pub update_label: &'static str,
    /// Значение поля: где обновиться.
    pub update_in_settings: &'static str,
    /// Заголовок окна с предложением обновиться.
    pub update_title: &'static str,

    // --- значок в лотке ---
    /// Пункт меню значка: достать окно из лотка.
    pub tray_show: &'static str,
    /// Пункт меню значка: выйти из программы.
    pub tray_quit: &'static str,
}

static LANGUAGE: OnceLock<Language> = OnceLock::new();

/// Запоминает язык; второй вызов ничего не делает.
pub fn set_language(language: Language) {
    let _ = LANGUAGE.set(language);
}

/// Подписи текущего языка; умолчание — русский.
pub fn s() -> &'static Strings {
    match LANGUAGE.get() {
        Some(Language::En) => &en::STRINGS,
        Some(Language::Ru) | None => &ru::STRINGS,
    }
}

/// Подпись режима: те же слова, что у действий групп.
pub fn mode_label(mode: TunnelMode) -> &'static str {
    match mode {
        TunnelMode::Tunnel => s().action_tunnel,
        TunnelMode::Direct => s().action_direct,
        TunnelMode::Block => s().action_block,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Все языки; `Language` себя не перечисляет.
    const TABLES: [(&str, &Strings); 2] = [("ru", &ru::STRINGS), ("en", &en::STRINGS)];

    #[test]
    fn no_label_is_empty_in_any_language() {
        for (name, table) in TABLES {
            let all = [
                table.connected,
                table.connecting,
                table.reconnecting,
                table.disconnecting,
                table.disconnected,
                table.daemon_offline,
                table.daemon_stopping,
                table.connect,
                table.disconnect,
                table.save,
                table.probe,
                table.probe_stop,
                table.ping,
                table.remove,
                table.select_hint,
                table.edit,
                table.search,
                table.uploaded,
                table.downloaded,
                table.connections,
                table.no_profiles,
                table.no_answer,
                table.probing,
                table.millis,
                table.managed,
                table.add_server,
                table.choose_protocol,
                table.subscription,
                table.subscription_key_hint,
                table.subscription_refresh,
                table.subscription_updated,
                table.subscription_failed,
                table.countries_failed,
                table.wireguard_add,
                table.wireguard_manual,
                table.wireguard_from_conf,
                table.import_conf_title,
                table.wireguard_configs,
                table.import_conf_failed,
                table.protocol_unknown,
                table.username,
                table.proxy_address,
                table.socks_address_example,
                table.optional_hint,
                table.proxy_udp,
                table.proxy_udp_plain,
                table.vmess_id,
                table.need_vmess_id,
                table.alter_id,
                table.bad_alter_id,
                table.vmess_zero_warning,
                table.new_server,
                table.edit_server,
                table.server_name,
                table.server_address,
                table.password,
                table.sni,
                table.transport,
                table.method,
                table.uuid,
                table.security,
                table.congestion,
                table.udp_mode,
                table.need_uuid,
                table.bad_uuid,
                table.link_no_uuid,
                table.link_unsupported_transport,
                table.need_method,
                table.path,
                table.path_example,
                table.http_host,
                table.obfs,
                table.need_username,
                table.bandwidth_up,
                table.bandwidth_down,
                table.insecure,
                table.chain_fingerprint,
                table.chain_fingerprint_example,
                table.private_key,
                table.need_private_key,
                table.server_public_key,
                table.need_server_public_key,
                table.preshared_key,
                table.interface_address,
                table.interface_address_example,
                table.need_interface_address,
                table.interface_address_v6,
                table.tunnel_dns,
                table.tunnel_dns_example,
                table.mtu,
                table.mtu_example,
                table.keepalive,
                table.keepalive_example,
                table.authorization,
                table.masque_udp_only,
                table.masque_ip_no_dns,
                table.reality_unverified,
                table.reality_public_key_example,
                table.reality_short_id,
                table.reality_short_id_example,
                table.reality_server_name,
                table.reality_server_name_example,
                table.flow,
                table.flow_example,
                table.pingwin_key_example,
                table.desync_strategy,
                table.need_server,
                table.need_password,
                table.bad_server,
                table.mode,
                table.rest,
                table.rest_hint,
                table.no_rules,
                table.rule,
                table.condition,
                table.action,
                table.rule_off,
                table.toggle_hint,
                table.probe_rule,
                table.rule_probe,
                table.probe_hint,
                table.destination,
                table.process,
                table.rule_name,
                table.apps_section,
                table.hosts_section,
                table.hosts_hint,
                table.ports_section,
                table.ports_hint,
                table.empty_means_any,
                table.sections_hint,
                table.host_exact,
                table.host_keyword,
                table.values_empty,
                table.values_not_found,
                table.add_rule,
                table.new_rule,
                table.edit_rule,
                table.unnamed_rule,
                table.app_search,
                table.no_apps,
                table.nothing_found,
                table.pick_app,
                table.pick_app_title,
                table.programs,
                table.pick_failed,
                table.import_rules,
                table.import_title,
                table.rule_lists,
                table.import_failed,
                table.import_empty,
                table.imported_groups,
                table.skipped_lines,
                table.export_rules,
                table.export_title,
                table.export_failed,
                table.exported_groups,
                table.skipped_groups,
                table.log_hint,
                table.copied,
                table.to_tail,
                table.flow_rule,
                table.decided_now,
                table.catch_address,
                table.catch_app,
                table.path_unknown,
                table.into_group,
                table.new_group,
                table.add,
                table.added_to_group,
                table.level_error,
                table.level_warning,
                table.on,
                table.off,
                table.startup,
                table.network,
                table.log,
                table.autostart,
                table.autoconnect,
                table.kill_switch,
                table.allow_lan,
                table.capture_default_route,
                table.dns_hijack,
                table.verbose_log,
                table.updates,
                table.check_updates,
                table.version,
                table.update_available,
                table.update_latest,
                table.update_checking,
                table.update_installing,
                table.update_restarting,
                table.update_failed,
                table.update_check,
                table.update_install,
                table.update_label,
                table.update_in_settings,
                table.update_title,
                table.tray_show,
                table.tray_quit,
            ];

            for label in all.into_iter().chain(table.screens) {
                assert!(!label.trim().is_empty(), "пустая подпись в языке `{name}`");
            }
        }
    }

    #[test]
    fn tunnel_states_are_told_apart() {
        for (name, table) in TABLES {
            let labels = [
                table.connected,
                table.connecting,
                table.reconnecting,
                table.disconnecting,
                table.disconnected,
            ];
            let unique: std::collections::HashSet<&str> = labels.into_iter().collect();
            assert_eq!(
                unique.len(),
                labels.len(),
                "совпадающие состояния в языке `{name}`"
            );
        }
    }

    #[test]
    fn actions_are_told_apart() {
        for (name, table) in TABLES {
            let labels = [table.action_tunnel, table.action_direct, table.action_block];
            let unique: std::collections::HashSet<&str> = labels.into_iter().collect();
            assert_eq!(
                unique.len(),
                labels.len(),
                "совпадающие действия в языке `{name}`"
            );
        }
    }

    #[test]
    fn the_default_language_is_russian() {
        assert_eq!(s().save, ru::STRINGS.save);
    }
}
