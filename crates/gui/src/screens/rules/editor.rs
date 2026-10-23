//! Модальное окно группы: имя, что забирает, куда отправляет.
//!
//! Что забирает — три раздела вкладками: «приложения, и сайты, и порты»; на
//! вкладке — сколько в разделе значений, пустой раздел — «любые». Вкладки, а
//! не три списка подряд: в группе бывают сотни доменов, и строкой они не
//! влезают, а тремя списками — не влезает окно.
//!
//! Приложения приходят от службы (у окна нет прав узнать путь чужого процесса),
//! но это только запущенное, поэтому есть выбор файла; выбранное встаёт в список
//! первой строкой.

use iced::Element;
use iced::theme::Palette;
use penguin_core::network::Network;
use penguin_ipc::schema::AppInfo;
use uikit::layout::{Flex, gap};
use uikit::tokens::type_scale;
use uikit::widgets::{Button, ButtonVariant, Checkbox, Modal, TextInput, modal};

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::forms::rule::{Action, Draft, Section};
use crate::screens::rules::values;
use crate::ui;

/// Ширина окна — как у окна профиля.
const WIDTH: f32 = 620.0;

/// Высота списка приложений: фиксированная (растянутое схлопнулось бы в ноль),
/// вместе с остальными разделами помещается в наименьшее окно.
const LIST_HEIGHT: f32 = 140.0;

/// Наибольшая длина пути в строке списка в знаках.
const PATH_WIDTH: usize = 52;

/// Собирает модальное окно группы.
pub fn view<'a>(state: &'a State, draft: &'a Draft) -> Element<'a, Message> {
    let strings = crate::i18n::s();
    let palette = &state.palette;
    let open = state.split_tunnel.section;

    let body = match open {
        Section::Apps => apps(state, draft),
        Section::Hosts | Section::Ports => values::view(state, draft, open, LIST_HEIGHT),
    };
    let catches = Flex::col()
        .push_auto(tabs(draft, open))
        .push_auto(body)
        .gap(gap::SM)
        .build();

    let form = Flex::col()
        .push_auto(
            TextInput::new(strings.rule_name, &draft.name)
                .on_input(|value| Message::SplitTunnel(SplitTunnelMessage::DraftNameChanged(value)))
                .build(),
        )
        .push_auto(catches)
        .push_auto(section(palette, strings.traffic, traffic(draft)))
        .push_auto(section(palette, strings.action, actions(draft)))
        .push_auto(problem(state))
        .gap(gap::MD)
        .build();

    let title = match draft.index {
        Some(_) => strings.edit_rule,
        None => strings.new_rule,
    };

    // `Esc` и нажатие мимо панели — «Отмена».
    Modal::new(form)
        .title(title)
        .max_width(WIDTH)
        .on_close(Message::SplitTunnel(SplitTunnelMessage::EditorClosed))
        .on_backdrop(Message::SplitTunnel(SplitTunnelMessage::EditorClosed))
        .build()
        .into()
}

/// Подпись раздела над его полем.
fn section<'a>(
    palette: &Palette,
    title: &'a str,
    body: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    Flex::col()
        .push_auto(ui::faint(palette, title, type_scale::MICRO))
        .push_auto(body)
        .gap(gap::XS)
        .build()
}

/// Вкладки разделов: открытый — акцентом, на каждой — сколько в нём значений.
fn tabs<'a>(draft: &Draft, open: Section) -> Element<'a, Message> {
    let mut row = Flex::row();
    for section in Section::ALL {
        let variant = if section == open {
            ButtonVariant::Primary
        } else {
            ButtonVariant::Secondary
        };
        // Подпись собирается здесь же, а `ui::button` берёт её взаймы.
        let label = iced::widget::text(tab_label(draft, section)).size(type_scale::BODY);
        row = row.push_auto(Button::new(label).variant(variant).hug().on_press(
            Message::SplitTunnel(SplitTunnelMessage::DraftSectionSelected(section)),
        ));
    }
    row.gap(gap::SM).build()
}

/// Подпись вкладки: имя раздела и число значений, пустой — «любые».
pub fn tab_label(draft: &Draft, section: Section) -> String {
    let strings = crate::i18n::s();
    let name = match section {
        Section::Apps => strings.apps_section,
        Section::Hosts => strings.hosts_section,
        Section::Ports => strings.ports_section,
    };
    match draft.values(section).len() {
        0 => format!("{name} · {}", strings.empty_means_any),
        count => format!("{name} · {count}"),
    }
}

/// Вид трафика: любой, TCP или UDP; выбранный — акцентом.
fn traffic<'a>(draft: &Draft) -> Element<'a, Message> {
    let choices = [
        (None, crate::i18n::s().traffic_any),
        (Some(Network::Tcp), "TCP"),
        (Some(Network::Udp), "UDP"),
    ];
    let mut row = Flex::row();
    for (network, label) in choices {
        let variant = if network == draft.network {
            ButtonVariant::Primary
        } else {
            ButtonVariant::Secondary
        };
        row = row.push_auto(ui::button(variant, label).on_press(Message::SplitTunnel(
            SplitTunnelMessage::DraftNetworkSelected(network),
        )));
    }
    row.gap(gap::SM).build()
}

/// Куда отправить: три кнопки, выбранная — акцентом; справа ответ окна.
///
/// Ответ не в подвале `Modal`: появляясь, подвал не влезал в окно и сминал
/// форму. Здесь он стоит всегда, и высота формы от выбора не меняется.
fn actions<'a>(draft: &Draft) -> Element<'a, Message> {
    let mut row = Flex::row();
    for action in Action::ALL {
        let variant = if action == draft.action {
            ButtonVariant::Primary
        } else {
            ButtonVariant::Secondary
        };
        row = row.push_auto(
            ui::button(variant, action.label()).on_press(Message::SplitTunnel(
                SplitTunnelMessage::DraftActionSelected(action),
            )),
        );
    }

    let strings = crate::i18n::s();
    let label = match draft.index {
        Some(_) => strings.save,
        None => strings.add_rule,
    };
    // Без условий группа совпала бы со всем подряд — ответа нет.
    let mut answer = ui::button(ButtonVariant::Primary, label);
    if !draft.is_empty() {
        answer = answer.on_press(Message::SplitTunnel(SplitTunnelMessage::DraftSaved));
    }

    row.push(ui::spring())
        .push_auto(modal::line(">"))
        .push_auto(answer)
        .gap(gap::SM)
        .build()
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

/// Строка под формой: неоткрывшееся окно выбора иначе делает кнопку «сломанной».
fn problem(state: &State) -> Element<'_, Message> {
    match state.split_tunnel.pick_error.as_ref() {
        Some(reason) => ui::muted(&state.palette, reason, type_scale::MICRO),
        None => ui::spring(),
    }
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
