//! Форма нового правила: имя, действие, адреса и список приложений.
//!
//! Адреса, домены и порты вводятся **одной строкой** и разбираются по виду.
//! Три отдельных поля заставляли бы пользователя знать, чем подсеть отличается
//! от домена, — а он знает только, что хочет пустить мимо тоннеля
//! `10.0.0.0/8`, `local.dev` и `445`.
//!
//! Приложения приходят от службы: у окна нет прав, чтобы узнать путь чужого
//! процесса, а без пути правило не написать — по имени файла его писать можно,
//! но небезопасно.

use iced::widget::text;
use iced::{Alignment, Element};
use penguin_ipc::schema::AppInfo;
use uikit::layout::{Flex, Sizable, Size, gap, grow, px};
use uikit::style::tokens::type_scale;
use uikit::widgets::{Button, ButtonVariant, Checkbox, Select, TextInput};

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::forms::rule::Action;
use crate::ui;

/// Сколько строк списка приложений показывать без прокрутки.
///
/// Список запущенного — полторы сотни строк; без ограничения он выдавливает с
/// экрана и форму правила, и всё остальное.
const LIST_HEIGHT: f32 = 200.0;

/// Собирает раздел «новое правило».
pub fn view(state: &State) -> Element<'_, Message> {
    let palette = &state.palette;
    let draft = &state.split_tunnel.draft;

    let top = Flex::row()
        .push_sized(
            TextInput::new(crate::i18n::s().rule_name, &draft.name)
                .on_input(|value| Message::SplitTunnel(SplitTunnelMessage::DraftNameChanged(value)))
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
        .align(Alignment::Center)
        .build();

    let addresses = TextInput::new(crate::i18n::s().addresses_hint, &draft.addresses)
        .on_input(|value| Message::SplitTunnel(SplitTunnelMessage::DraftAddressesChanged(value)))
        .build();

    // Во всю ширину и невысокая: это завершение формы, а не действие где-то
    // сбоку от неё, и искать его глазами человек не должен.
    let mut add = Button::new(
        text(crate::i18n::s().add_rule)
            .size(type_scale::BODY)
            .align_x(iced::alignment::Horizontal::Center)
            .width(iced::Length::Fill),
    )
    .variant(ButtonVariant::Primary)
    .w(Size::FILL)
    .h(px(ADD_HEIGHT));

    // Кнопка без условий собрала бы правило, совпадающее со всем подряд.
    if !draft.is_empty() {
        add = add.on_press(Message::SplitTunnel(SplitTunnelMessage::RuleAdded));
    }

    let unknown = draft.unknown();
    let footer = Flex::row()
        .push(if unknown.is_empty() {
            ui::spring()
        } else {
            // Молча выбросить непонятое нельзя: правило соберётся, но не тем,
            // чего ждали, и разбираться человек будет уже по последствиям.
            ui::muted(
                palette,
                format!(
                    "{}: {}",
                    crate::i18n::s().not_recognised,
                    unknown.join(", ")
                ),
                type_scale::MICRO,
            )
        })
        .gap(gap::SM)
        .align(Alignment::Center)
        .build();

    let content = Flex::col()
        .push_auto(top)
        .push_auto(addresses)
        .push_auto(apps(state))
        .push_auto(footer)
        .push_auto(add)
        .gap(gap::MD)
        .build();

    ui::section(palette, crate::i18n::s().new_rule, None, content)
}

/// Список запущенных приложений с отметками.
fn apps(state: &State) -> Element<'_, Message> {
    let palette = &state.palette;
    let split = &state.split_tunnel;

    let search = TextInput::new(crate::i18n::s().app_search, &split.app_search)
        .on_input(|value| Message::SplitTunnel(SplitTunnelMessage::AppSearchChanged(value)))
        .build();

    let shown = filter(&split.running_apps, &split.app_search);

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
            .map(|app| row(state, app, split.draft.has_process(&app.path)))
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
fn row<'a>(state: &'a State, app: &'a AppInfo, checked: bool) -> Element<'a, Message> {
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
            &state.palette,
            shorten(&app.path, PATH_WIDTH),
            type_scale::MICRO,
        ))
        .gap(gap::SM)
        .align(Alignment::Center)
        .build()
}

/// Наибольшая длина пути в строке списка.
///
/// Полный путь внутри пакета Windows занимает две строки машинных
/// идентификаторов и растягивает окно; выбирают же приложение по имени файла и
/// по началу пути.
const PATH_WIDTH: usize = 52;

/// Высота кнопки «Добавить правило».
const ADD_HEIGHT: f32 = 30.0;

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
        let path = r"D:\WpSystem\S-1-5-21-2960677031-2112851187-709588018-1001\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude-code.1.247\claude.exe";
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
        // Самое частое состояние: экран открыт, ответ службы ещё не пришёл.
        let state = State::default();
        assert!(state.split_tunnel.running_apps.is_empty());
        let _ = view(&state);
    }

    #[test]
    fn renders_with_apps_and_marks() {
        let mut state = State::default();
        state.split_tunnel.running_apps = apps_list();
        state
            .split_tunnel
            .draft
            .toggle_process("c:/games/steam/steam.exe", true);
        let _ = view(&state);
    }

    #[test]
    fn unrecognised_input_is_shown() {
        let mut state = State::default();
        state.split_tunnel.draft.addresses = "example.com ???".to_owned();
        assert_eq!(state.split_tunnel.draft.unknown(), ["???"]);
        let _ = view(&state);
    }

    #[test]
    fn the_list_does_not_take_over_the_screen() {
        // Полторы сотни строк без ограничения высоты выдавливают с экрана саму
        // форму правила.
        const { assert!(LIST_HEIGHT <= 280.0) };
    }
}
