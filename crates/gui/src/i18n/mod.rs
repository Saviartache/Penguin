//! Локализация интерфейса.
//!
//! Подписи собраны в **одну структуру** [`Strings`], а каждый язык — это одно
//! её значение ([`ru::STRINGS`], [`en::STRINGS`]). Не файлы с ключами и не
//! словарь: словарь отвечает на отсутствующий ключ во время работы, а
//! структура — во время сборки. Забыть перевести подпись при таком устройстве
//! нельзя, потому что новое поле обязаны заполнить оба языка.
//!
//! Собраны они в одном месте не только ради перевода. Подпись, разбросанная
//! по трём экранам в трёх написаниях, расходится сама собой: «Подключиться»,
//! «Подключить» и «Соединиться» в одном окне.
//!
//! Язык выбирается один раз при запуске — из настроек, до первой отрисовки.
//! Менять его на ходу нельзя намеренно: половина окна успела бы отрисоваться
//! на одном языке, половина на другом, а выигрыш — избавить пользователя от
//! перезапуска, который он делает раз в жизни.

pub mod en;
pub mod ru;

use std::sync::OnceLock;

use penguin_config::schema::app::Language;

/// Все подписи окна.
///
/// Поля, а не ключи: новое поле не собирается, пока его не заполнят оба языка.
#[derive(Debug, Clone, Copy)]
pub struct Strings {
    // --- вкладки ---
    /// Подписи вкладок в порядке [`crate::app::Screen::ALL`].
    ///
    /// Массив, а не список: расхождение числа подписей и числа экранов
    /// означало бы, что часть экранов недостижима, — и это ловится сборкой,
    /// а не глазами.
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
    /// Служба останавливается вместе с окном.
    pub service_stopping: &'static str,

    // --- действия ---
    /// Включить тоннель.
    pub connect: &'static str,
    /// Выключить тоннель.
    pub disconnect: &'static str,
    /// Сохранить изменения.
    pub save: &'static str,
    /// Проверить.
    pub probe: &'static str,
    /// Удалить.
    pub remove: &'static str,
    /// Как выбрать профиль — подсказкой у нижнего края списка.
    ///
    /// Кнопки «Выбрать» в строке больше нет: выбирает щелчок по самой строке.
    /// Действие, у которого не осталось своего элемента управления, обязано
    /// быть где-то написано словами.
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
    /// Пример адреса прокси HTTP.
    pub http_address_example: &'static str,
    /// Пример адреса прокси HTTPS.
    pub https_address_example: &'static str,
    /// Поле можно не заполнять — подсказкой внутри него.
    pub optional_hint: &'static str,
    /// Пускать ли UDP через прокси.
    pub proxy_udp: &'static str,
    /// То же, но под TLS: датаграммы в него не заворачиваются.
    ///
    /// Отдельная подпись, а не примечание рядом: человек, выбравший «SOCKS5
    /// под TLS», иначе будет считать защищённым то, что не защищено, — а
    /// каждый запрос DNS уходит именно так.
    pub proxy_udp_plain: &'static str,
    /// Имя для TLS.
    pub sni: &'static str,
    /// Чем переносится поток: голый TCP, WebSocket, `Upgrade`.
    pub transport: &'static str,
    /// Метод шифрования.
    pub method: &'static str,
    /// UUID пользователя.
    pub uuid: &'static str,
    /// Чем шифруется соединение до сервера.
    pub security: &'static str,
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
    /// Отдача.
    pub bandwidth_up: &'static str,
    /// Приём.
    pub bandwidth_down: &'static str,
    /// Не проверять сертификат.
    pub insecure: &'static str,
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
    /// В ссылке нет порта.
    pub link_no_port: &'static str,

    // --- правила ---
    /// Режим тоннелирования.
    pub mode: &'static str,
    /// Подписи режимов в порядке [`MODE_VALUES`].
    pub modes: [&'static str; 4],
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
    ///
    /// Флажка в строке нет: строка и есть переключатель. Действие, у которого
    /// не осталось своего элемента управления, обязано быть написано словами.
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
    /// Что можно вписать в строку адресов.
    pub addresses_hint: &'static str,
    /// Добавить правило.
    pub add_rule: &'static str,
    /// Новое правило.
    pub new_rule: &'static str,
    /// Не удалось опознать.
    pub not_recognised: &'static str,
    /// Имя правила, которое не назвали.
    pub unnamed_rule: &'static str,
    /// Действие «мимо тоннеля».
    pub action_direct: &'static str,
    /// Действие «в тоннель».
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
    /// Запускать при входе в систему.
    pub autostart: &'static str,
    /// Подключаться при запуске.
    pub autoconnect: &'static str,
    /// Kill switch.
    pub kill_switch: &'static str,
    /// Локальная сеть мимо тоннеля.
    pub allow_lan: &'static str,
}

/// Значения режимов в том порядке, в каком они показываются.
///
/// Не переводятся: это то, что лежит в файле настроек и что понимает
/// маршрутизатор. Подписи к ним — [`Strings::modes`].
pub const MODE_VALUES: [&str; 4] = ["full", "allowlist", "blocklist", "off"];

/// Выбранный язык. Ставится один раз при запуске.
static LANGUAGE: OnceLock<Language> = OnceLock::new();

/// Запоминает язык интерфейса.
///
/// Второй вызов ничего не делает: язык выбирается до первой отрисовки, а
/// смена его на ходу оставила бы половину окна на прежнем языке.
pub fn set_language(language: Language) {
    let _ = LANGUAGE.set(language);
}

/// Подписи текущего языка.
pub fn s() -> &'static Strings {
    match LANGUAGE.get() {
        Some(Language::En) => &en::STRINGS,
        // Умолчание — русский: язык, на котором окно писалось и на котором
        // подписи заведомо помещаются в отведённое им место.
        Some(Language::Ru) | None => &ru::STRINGS,
    }
}

/// Подпись режима по его значению в файле настроек.
pub fn mode_label(mode: &str) -> &'static str {
    mode_index(mode).map_or("", |index| s().modes[index])
}

/// Место режима в [`MODE_VALUES`].
fn mode_index(mode: &str) -> Option<usize> {
    MODE_VALUES.iter().position(|known| *known == mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Все языки, какие есть. Перечисление здесь, а не в цикле по `Language`:
    /// у него нет способа перечислить себя, а пропущенный язык — это язык без
    /// проверок.
    const TABLES: [(&str, &Strings); 2] = [("ru", &ru::STRINGS), ("en", &en::STRINGS)];

    #[test]
    fn every_mode_has_a_label() {
        // Режим без подписи выглядит в списке пустой строкой, и выбрать его
        // невозможно.
        for mode in MODE_VALUES {
            assert!(!mode_label(mode).is_empty(), "нет подписи для `{mode}`");
        }
        assert_eq!(mode_label("нет такого"), "");
    }

    #[test]
    fn mode_values_match_the_config() {
        // Значения уезжают в файл настроек; расхождение с тем, что понимает
        // маршрутизатор, сделало бы выбор режима бесполезным.
        for mode in MODE_VALUES {
            assert!(
                crate::app::update::rules::parse_mode(mode).is_some(),
                "режим `{mode}` не разбирается"
            );
        }
    }

    #[test]
    fn no_label_is_empty_in_any_language() {
        // Пустая подпись — это элемент, по которому не понять, что он делает.
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
                table.protocol_unknown,
                table.username,
                table.proxy_address,
                table.socks_address_example,
                table.http_address_example,
                table.https_address_example,
                table.optional_hint,
                table.proxy_udp,
                table.proxy_udp_plain,
                table.link_no_port,
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
                table.need_uuid,
                table.bad_uuid,
                table.link_no_uuid,
                table.need_method,
                table.path,
                table.path_example,
                table.http_host,
                table.obfs,
                table.bandwidth_up,
                table.bandwidth_down,
                table.insecure,
                table.need_server,
                table.need_password,
                table.bad_server,
                table.mode,
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
                table.addresses_hint,
                table.add_rule,
                table.new_rule,
                table.not_recognised,
                table.unnamed_rule,
                table.app_search,
                table.no_apps,
                table.nothing_found,
                table.pick_app,
                table.pick_app_title,
                table.programs,
                table.pick_failed,
                table.level_error,
                table.level_warning,
                table.on,
                table.off,
                table.startup,
                table.network,
                table.autostart,
                table.autoconnect,
                table.kill_switch,
                table.allow_lan,
            ];

            for label in all.into_iter().chain(table.screens).chain(table.modes) {
                assert!(!label.trim().is_empty(), "пустая подпись в языке `{name}`");
            }
        }
    }

    #[test]
    fn tunnel_states_are_told_apart() {
        // Одинаковые подписи у разных состояний означают окно, по которому не
        // понять, что происходит.
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
    fn modes_are_told_apart() {
        for (name, table) in TABLES {
            let unique: std::collections::HashSet<&str> = table.modes.into_iter().collect();
            assert_eq!(
                unique.len(),
                table.modes.len(),
                "совпадающие режимы в языке `{name}`"
            );
        }
    }

    #[test]
    fn the_default_language_is_russian() {
        // Окно писалось на русском, и подписи заведомо помещаются в
        // отведённое им место только на нём.
        assert_eq!(s().save, ru::STRINGS.save);
    }
}
