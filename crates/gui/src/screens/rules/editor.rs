//! Модальное окно нового правила: имя, действие, адреса и список приложений.
//!
//! Адреса, домены и порты — одной строкой, разбор по виду. Приложения приходят от
//! службы (у окна нет прав узнать путь чужого процесса), но это только запущенное,
//! поэтому есть выбор файла; выбранное встаёт в список первой строкой.

use iced::Element;
use iced::theme::Palette;
use penguin_ipc::schema::AppInfo;
use uikit::layout::{Flex, gap, grow};
use uikit::tokens::type_scale;
use uikit::widgets::{ButtonVariant, Checkbox, Modal, Select, TextInput};

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::forms::rule::{Action, Draft};
use crate::ui;

/// Ширина окна — как у окна профиля.
const WIDTH: f32 = 620.0;

/// Высота списка приложений: фиксированная (растянутое схлопнулось бы в ноль),
/// помещается в наименьшее окно.
const LIST_HEIGHT: f32 = 180.0;

/// Наибольшая длина пути в строке списка в знаках.
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

    // `Esc` и нажатие мимо панели — «Отмена».
    let mut modal = Modal::new(form)
        .title(crate::i18n::s().new_rule)
        .max_width(WIDTH)
        .on_close(Message::SplitTunnel(SplitTunnelMessage::EditorClosed))
        .on_backdrop(Message::SplitTunnel(SplitTunnelMessage::EditorClosed));

    // Без условий правило совпало бы со всем подряд — ответа нет.
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

    // Пока системное окно открыто, второе такое же не нужно.
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

    // Выбранное файлом собирается на каждой отрисовке: отдельного списка нет,
    // список — само правило.
    let picked = picked_apps(&split.running_apps, &draft.processes);
    let mut shown = filter(&picked, &split.app_search);
    shown.extend(filter(&split.running_apps, &split.app_search));

    let list: Element<'_, Message> = if shown.is_empty() {
        // Две причины, и действия от человека разные.
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

/// Строка списка; ничего не заимствует у приложения, список пересобирается.
fn row<'a>(palette: &Palette, app: &AppInfo, checked: bool) -> Element<'a, Message> {
    let path = app.path.clone();

    Flex::row()
        .push_auto(Checkbox::new(label(app), checked).on_toggle(move |value| {
            Message::SplitTunnel(SplitTunnelMessage::AppToggled(path.clone(), value))
        }))
        .push(ui::spring())
        .push_auto(ui::faint(
            palette,
            shorten(&app.path, PATH_WIDTH),
            type_scale::MICRO,
        ))
        .gap(gap::SM)
        .align(iced::Alignment::Center)
        .build()
}

/// Строка под формой: причина сразу, не по нажатию. Непонятое молча выбрасывать
/// нельзя, неоткрывшееся окно выбора иначе делает кнопку «сломанной».
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

/// Отмеченные приложения, которых нет среди запущенных: стоят первыми и снимаются
/// тем же флажком, иначе отметку не видно.
pub fn picked_apps(running: &[AppInfo], chosen: &[String]) -> Vec<AppInfo> {
    chosen
        .iter()
        .filter(|path| !running.iter().any(|app| &app.path == *path))
        .map(|path| AppInfo {
            name: penguin_core::path::file_name(path).to_owned(),
            path: path.clone(),
            // Запущенных копий нет.
            instances: 0,
        })
        .collect()
}

/// Выбрасывает середину пути, оставляя начало и конец; по знакам, не по байтам.
pub fn shorten(path: &str, width: usize) -> String {
    let count = path.chars().count();
    if count <= width {
        return path.to_owned();
    }

    // Хвост длиннее головы: имя файла опознаётся сразу.
    let tail = width.saturating_sub(4) * 2 / 3;
    let head = width.saturating_sub(tail + 1);

    let start: String = path.chars().take(head).collect();
    let end: String = path.chars().skip(count - tail).collect();
    format!("{start}…{end}")
}

/// Подпись приложения; число копий — только если их больше одной.
pub fn label(app: &AppInfo) -> String {
    if app.instances > 1 {
        format!("{} ({})", app.name, app.instances)
    } else {
        app.name.clone()
    }
}

/// Отбирает приложения по строке поиска: по имени и по пути.
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
        let path = format!("D:/Программы/{}/приложение.exe", "п".repeat(100));
        let short = shorten(&path, PATH_WIDTH);
        assert_eq!(short.chars().count(), PATH_WIDTH);
    }

    #[test]
    fn search_looks_at_the_name_and_the_path() {
        let apps = apps_list();
        assert_eq!(filter(&apps, "chrome").len(), 1);
        assert_eq!(filter(&apps, "games").len(), 1);
        assert_eq!(filter(&apps, "").len(), 2);
        assert!(filter(&apps, "нет такого").is_empty());
        assert_eq!(filter(&apps, "  CHROME  ").len(), 1);
    }

    #[test]
    fn renders_without_apps() {
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
        let running = apps_list();
        let chosen = [running[1].path.clone()];

        assert!(picked_apps(&running, &chosen).is_empty());
    }

    #[test]
    fn the_chosen_program_comes_first() {
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
        let mut state = State::default();
        state.split_tunnel.picking = true;
        let _ = view(&state, &Draft::default());
    }

    #[test]
    fn a_window_that_did_not_open_says_so() {
        let mut state = State::default();
        state.split_tunnel.pick_error = Some("Не удалось открыть окно выбора".to_owned());
        let _ = view(&state, &Draft::default());
    }

    #[test]
    fn the_window_fits_the_smallest_window() {
        const { assert!(LIST_HEIGHT < crate::app::EXPANDED.height) };
    }
}
