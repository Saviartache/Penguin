//! Модальное окно нового правила: имя, действие, адреса и список приложений.
//!
//! Окно, а не раздел под таблицей. Форма из четырёх полей плюс список
//! запущенного в полторы сотни строк отодвигали саму таблицу за нижний край, и
//! человек писал правило, не видя тех, что уже есть, — тогда как новое правило
//! почти всегда пишут, глядя на соседнее, и половина ошибок в наборе от того,
//! что два правила спорят.
//!
//! Адреса, домены и порты вводятся **одной строкой** и разбираются по виду.
//! Три отдельных поля заставляли бы пользователя знать, чем подсеть отличается
//! от домена, — а он знает только, что хочет пустить мимо тоннеля
//! `10.0.0.0/8`, `local.dev` и `445`.
//!
//! Приложения приходят от службы: у окна нет прав, чтобы узнать путь чужого
//! процесса, а без пути правило не написать — по имени файла его писать можно,
//! но небезопасно.
//!
//! Список от службы — только про **запущенное**, и этого мало: правило пишут и
//! для игры, в которую сегодня не играли, и для обновлятора, который
//! просыпается сам раз в неделю. Их показывают файлом, через системное окно
//! выбора, и выбранное встаёт в тот же список первой строкой: отметка, которой
//! не видно, читается как «не сработало».

use iced::Element;
use iced::theme::Palette;
use penguin_ipc::schema::AppInfo;
use uikit::layout::{Flex, gap, grow};
use uikit::style::tokens::type_scale;
use uikit::widgets::{ButtonVariant, Checkbox, Modal, Select, TextInput};

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::forms::rule::{Action, Draft};
use crate::ui;

/// Ширина окна.
///
/// Та же, что у окна профиля: два модальных окна разной ширины в одной
/// программе читаются как два разных диалога.
const WIDTH: f32 = 620.0;

/// Высота списка приложений.
///
/// Фиксированная, а не «сколько поместится»: растянутое содержимое в панели
/// «по содержимому» схлопывается в ноль, а ноль роняет отрисовку. Значение
/// подобрано так, чтобы окно целиком помещалось в наименьшее окно программы.
const LIST_HEIGHT: f32 = 180.0;

/// Наибольшая длина пути в строке списка.
///
/// Полный путь внутри пакета Windows занимает две строки машинных
/// идентификаторов и растягивает окно; выбирают же приложение по имени файла и
/// по началу пути.
const PATH_WIDTH: usize = 52;

/// Собирает модальное окно нового правила.
pub fn view<'a>(state: &'a State, draft: &'a Draft) -> Element<'a, Message> {
    let form = Flex::col()
        .push_auto(
            Flex::row()
                .push_sized(
                    TextInput::new(crate::i18n::s().rule_name, &draft.name)
                        .on_input(|value| {
                            Message::SplitTunnel(SplitTunnelMessage::DraftNameChanged(value))
                        })
                        .build(),
                    grow(3),
                )
                .push_sized(
                    Select::new(Action::ALL, Some(draft.action), |action| {
                        Message::SplitTunnel(SplitTunnelMessage::DraftActionSelected(action))
                    })
                    .view(),
                    grow(2),
                )
                .gap(gap::SM)
                .align(iced::Alignment::Center)
                .build(),
        )
        .push_auto(
            TextInput::new(crate::i18n::s().addresses_hint, &draft.addresses)
                .on_input(|value| {
                    Message::SplitTunnel(SplitTunnelMessage::DraftAddressesChanged(value))
                })
                .build(),
        )
        .push_auto(apps(state, draft))
        .push_auto(problem(state, draft))
        .gap(gap::MD)
        .build();

    let mut modal = Modal::new(form)
        .title(crate::i18n::s().new_rule)
        .max_width(WIDTH)
        // `Esc` и нажатие мимо панели означают «Отмена»: отдельной кнопки для
        // этого не нужно, а место в ряду ответов дорого.
        .on_close(Message::SplitTunnel(SplitTunnelMessage::EditorClosed))
        .on_backdrop(Message::SplitTunnel(SplitTunnelMessage::EditorClosed));

    // Ответа нет, пока правилу нечем сработать: правило без условий совпадает
    // со всем подряд, и добавить такое молча нельзя.
    if !draft.is_empty() {
        modal = modal.action(
            crate::i18n::s().add_rule,
            Message::SplitTunnel(SplitTunnelMessage::RuleAdded),
        );
    }

    modal.build().into()
}

/// Список приложений с отметками и кнопкой выбора файла.
fn apps<'a>(state: &'a State, draft: &'a Draft) -> Element<'a, Message> {
    let palette = &state.palette;
    let split = &state.split_tunnel;

    // Кнопка рядом с поиском, а не под списком: нажимают её ровно тогда, когда
    // поиск ничего не нашёл, — и рука уже здесь. Пока системное окно открыто,
    // нажимать нечего: второе такое же означало бы два ответа на один вопрос.
    let mut pick = ui::button(ButtonVariant::Secondary, crate::i18n::s().pick_app);
    if !split.picking {
        pick = pick.on_press(Message::SplitTunnel(SplitTunnelMessage::AppPickRequested));
    }

    let search = Flex::row()
        .push(
            TextInput::new(crate::i18n::s().app_search, &split.app_search)
                .on_input(|value| Message::SplitTunnel(SplitTunnelMessage::AppSearchChanged(value)))
                .build(),
        )
        .push_auto(pick)
        .gap(gap::SM)
        .align(iced::Alignment::Center)
        .build();

    // Выбранное файлом собирается здесь и живёт только эту отрисовку: списка,
    // в котором оно лежало бы вместе с запущенным, нет — правило и есть такой
    // список.
    let picked = picked_apps(&split.running_apps, &draft.processes);
    let mut shown = filter(&picked, &split.app_search);
    shown.extend(filter(&split.running_apps, &split.app_search));

    let list: Element<'_, Message> = if shown.is_empty() {
        // Пустой список без объяснения читается как «сломалось». Причин ровно
        // две, и они требуют разных действий от пользователя.
        let reason = if split.running_apps.is_empty() {
            crate::i18n::s().no_apps
        } else {
            crate::i18n::s().nothing_found
        };
        ui::empty(palette, reason)
    } else {
        let rows = shown
            .into_iter()
            .map(|app| row(palette, app, draft.has_process(&app.path)))
            .collect::<Vec<_>>();

        ui::scroll_box(Flex::col().extend(rows).gap(gap::XS).build(), LIST_HEIGHT)
    };

    Flex::col()
        .push_auto(search)
        .push_auto(list)
        .gap(gap::SM)
        .build()
}

/// Одна строка списка приложений.
///
/// У приложения ничего не занимает: строка переживает список, из которого её
/// собрали, — а список выбранного файлом собирается на каждой отрисовке
/// заново.
fn row<'a>(palette: &Palette, app: &AppInfo, checked: bool) -> Element<'a, Message> {
    let path = app.path.clone();

    Flex::row()
        .push_auto(Checkbox::new(label(app), checked).on_toggle(move |value| {
            Message::SplitTunnel(SplitTunnelMessage::AppToggled(path.clone(), value))
        }))
        .push(ui::spring())
        // Путь тише и правее: различают по нему, но читают его редко. И
        // серединой: у путей внутри пакетов она из машинных
        // идентификаторов, а концы — как раз то, по чему приложение и узнают.
        .push_auto(ui::faint(
            palette,
            shorten(&app.path, PATH_WIDTH),
            type_scale::MICRO,
        ))
        .gap(gap::SM)
        .align(iced::Alignment::Center)
        .build()
}

/// Что пошло не так — строкой под формой.
///
/// Бед две, и обе показываются сразу, а не по нажатию. Молча выбросить
/// непонятое нельзя: правило соберётся, но не тем, чего ждали, и разбираться
/// человек будет уже по последствиям. Не открывшееся окно выбора — то же
/// самое: без строки о нём кнопка выглядит сломанной.
fn problem<'a>(state: &'a State, draft: &'a Draft) -> Element<'a, Message> {
    let palette = &state.palette;
    let mut lines: Vec<Element<'a, Message>> = Vec::new();

    if let Some(reason) = state.split_tunnel.pick_error.as_ref() {
        lines.push(ui::muted(palette, reason, type_scale::MICRO));
    }

    let unknown = draft.unknown();
    if !unknown.is_empty() {
        lines.push(ui::muted(
            palette,
            format!(
                "{}: {}",
                crate::i18n::s().not_recognised,
                unknown.join(", ")
            ),
            type_scale::MICRO,
        ));
    }

    if lines.is_empty() {
        return ui::spring();
    }

    Flex::col().extend(lines).gap(gap::XS).build()
}

/// Отмеченные приложения, которых нет среди запущенных.
///
/// Показанная файлом программа обычно не запущена, и в списке от службы её
/// нет. Отметка, которой не видно, читается как «не сработало», и человек
/// показывает файл второй раз; поэтому выбранное встаёт в тот же список,
/// снимается тем же флажком и стоит первым — чтобы его было видно сразу.
pub fn picked_apps(running: &[AppInfo], chosen: &[String]) -> Vec<AppInfo> {
    chosen
        .iter()
        .filter(|path| !running.iter().any(|app| &app.path == *path))
        .map(|path| AppInfo {
            name: penguin_core::path::file_name(path).to_owned(),
            path: path.clone(),
            // Ни одной запущенной копии — про это и говорит ноль.
            instances: 0,
        })
        .collect()
}

/// Выбрасывает середину пути, оставляя начало и конец.
///
/// Свободная функция с тестом: обрезка не по знакам, а по байтам разрубила бы
/// кириллицу пополам, и в списке появились бы вопросительные знаки.
pub fn shorten(path: &str, width: usize) -> String {
    let count = path.chars().count();
    if count <= width {
        return path.to_owned();
    }

    // Хвост длиннее головы: имя файла и его каталог опознаются мгновенно, а
    // начало пути у всех приложений и так одинаковое.
    let tail = width.saturating_sub(4) * 2 / 3;
    let head = width.saturating_sub(tail + 1);

    let start: String = path.chars().take(head).collect();
    let end: String = path.chars().skip(count - tail).collect();
    format!("{start}…{end}")
}

/// Подпись приложения в списке.
///
/// Число копий показывается, только когда их больше одной: «steam.exe (1)» —
/// лишний шум, «chrome.exe (24)» — полезное знание.
pub fn label(app: &AppInfo) -> String {
    if app.instances > 1 {
        format!("{} ({})", app.name, app.instances)
    } else {
        app.name.clone()
    }
}

/// Отбирает приложения по строке поиска.
///
/// Ищет и по имени, и по пути: пользователь помнит либо одно, либо другое.
pub fn filter<'a>(apps: &'a [AppInfo], query: &str) -> Vec<&'a AppInfo> {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return apps.iter().collect();
    }

    apps.iter()
        .filter(|app| {
            app.name.to_lowercase().contains(&query) || app.path.to_lowercase().contains(&query)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apps_list() -> Vec<AppInfo> {
        vec![
            AppInfo {
                path: "c:/program files/google/chrome/chrome.exe".to_owned(),
                name: "chrome.exe".to_owned(),
                instances: 24,
            },
            AppInfo {
                path: "c:/games/steam/steam.exe".to_owned(),
                name: "steam.exe".to_owned(),
                instances: 1,
            },
        ]
    }

    #[test]
    fn instances_are_shown_only_when_there_are_several() {
        let apps = apps_list();
        assert_eq!(label(&apps[0]), "chrome.exe (24)");
        assert_eq!(label(&apps[1]), "steam.exe");
    }

    #[test]
    fn a_long_path_keeps_both_ends() {
        // Середину пути внутри пакета Windows занимают машинные
        // идентификаторы; узнают приложение по началу и по имени файла.
        let path = r"D:\WpSystem\S-1-5-21-2960677031-2112851187-709588018-1001\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude-code.1.247\claude.exe";
        let short = shorten(path, PATH_WIDTH);

        assert_eq!(short.chars().count(), PATH_WIDTH);
        assert!(short.starts_with("D:"), "начало пути потеряно: {short}");
        assert!(short.ends_with("claude.exe"), "имя файла потеряно: {short}");
        assert!(short.contains('…'), "не сказано, что путь урезан");
    }

    #[test]
    fn a_short_path_is_left_alone() {
        let path = "c:/windows/system32/svchost.exe";
        assert_eq!(shorten(path, PATH_WIDTH), path);
    }

    #[test]
    fn cyrillic_paths_are_cut_by_characters() {
        // Обрезка по байтам разрубила бы букву пополам, и в списке появились
        // бы вопросительные знаки.
        let path = format!("D:/Программы/{}/приложение.exe", "п".repeat(100));
        let short = shorten(&path, PATH_WIDTH);
        assert_eq!(short.chars().count(), PATH_WIDTH);
    }

    #[test]
    fn search_looks_at_the_name_and_the_path() {
        // Пользователь помнит либо имя, либо где оно установлено.
        let apps = apps_list();
        assert_eq!(filter(&apps, "chrome").len(), 1);
        assert_eq!(filter(&apps, "games").len(), 1);
        assert_eq!(filter(&apps, "").len(), 2);
        assert!(filter(&apps, "нет такого").is_empty());
        assert_eq!(filter(&apps, "  CHROME  ").len(), 1);
    }

    #[test]
    fn renders_without_apps() {
        // Самое частое состояние: окно открыто, ответ службы ещё не пришёл.
        let state = State::default();
        assert!(state.split_tunnel.running_apps.is_empty());
        let _ = view(&state, &Draft::default());
    }

    #[test]
    fn renders_with_apps_and_marks() {
        let mut state = State::default();
        state.split_tunnel.running_apps = apps_list();

        let mut draft = Draft::default();
        draft.toggle_process("c:/games/steam/steam.exe", true);
        let _ = view(&state, &draft);
    }

    #[test]
    fn an_empty_draft_offers_no_answer() {
        // Правило без условий совпало бы со всем подряд, и добавить такое
        // молча нельзя. Кнопка, которая ничего не делает, читается как
        // сломанная, поэтому её нет вовсе.
        let draft = Draft {
            name: "Пусто".to_owned(),
            ..Draft::default()
        };
        assert!(draft.is_empty());
        let _ = view(&State::default(), &draft);
    }

    #[test]
    fn unrecognised_input_is_shown() {
        let draft = Draft {
            addresses: "example.com ???".to_owned(),
            ..Draft::default()
        };
        assert_eq!(draft.unknown(), ["???"]);
        let _ = view(&State::default(), &draft);
    }

    #[test]
    fn a_program_chosen_by_file_joins_the_list() {
        // Она не запущена, и в списке от службы её нет. Отметка, которой не
        // видно, читается как «не сработало».
        let running = apps_list();
        let chosen = ["c:/games/doom/doom.exe".to_owned()];

        let picked = picked_apps(&running, &chosen);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].path, chosen[0]);
        assert_eq!(picked[0].name, "doom.exe", "имя файла взято не из пути");
        assert_eq!(picked[0].instances, 0, "не запущено ни одной копии");
    }

    #[test]
    fn a_running_program_is_not_listed_twice() {
        // Тот же файл можно и отметить в списке, и показать через окно
        // выбора: две одинаковые строки означали бы, что одна из них лишняя.
        let running = apps_list();
        let chosen = [running[1].path.clone()];

        assert!(picked_apps(&running, &chosen).is_empty());
    }

    #[test]
    fn the_chosen_program_comes_first() {
        // Ради этого список и собирается заново: только что выбранное должно
        // быть видно без прокрутки полутора сотен строк.
        let mut state = State::default();
        state.split_tunnel.running_apps = apps_list();

        let mut draft = Draft::default();
        draft.toggle_process("c:/games/doom/doom.exe", true);

        let picked = picked_apps(&state.split_tunnel.running_apps, &draft.processes);
        let mut shown = filter(&picked, "");
        shown.extend(filter(&state.split_tunnel.running_apps, ""));

        assert_eq!(shown[0].path, "c:/games/doom/doom.exe");
        assert_eq!(shown.len(), 3);
        let _ = view(&state, &draft);
    }

    #[test]
    fn the_button_goes_quiet_while_the_window_is_open() {
        // Второе системное окно поверх первого — два ответа на один вопрос.
        let mut state = State::default();
        state.split_tunnel.picking = true;
        let _ = view(&state, &Draft::default());
    }

    #[test]
    fn a_window_that_did_not_open_says_so() {
        // Без строки о беде кнопка выглядит сломанной.
        let mut state = State::default();
        state.split_tunnel.pick_error = Some("Не удалось открыть окно выбора".to_owned());
        let _ = view(&state, &Draft::default());
    }

    #[test]
    fn the_window_fits_the_smallest_window() {
        // Растянутое содержимое в панели «по содержимому» схлопывается в ноль,
        // поэтому высота списка фиксированная — и обязана помещаться.
        const { assert!(LIST_HEIGHT < crate::app::EXPANDED.height) };
    }
}
