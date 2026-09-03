//! Список профилей — символьная панель терминала во всю вкладку.
//!
//! Таблица, а не карточки: у профиля три значения — имя, адрес, задержка, — и
//! сравнивают их **между строками**, по столбцам. Карточки ставят те же
//! значения в разных местах каждой строки, и глазу приходится искать их заново
//! на каждом сервере.
//!
//! Сама таблица — общая: рамка, черта под шапкой, поиск, прокрутка и волна на
//! строке живут в [`crate::screens::table`], а здесь остаётся только то, что у
//! серверов своё, — какие столбцы и что в них.
//!
//! # Выбор — щелчок по строке
//!
//! Кнопки «Выбрать» в строке нет: строка и есть кнопка. Кнопка в каждой строке
//! повторяла то, что и так делает щелчок по записи в любом списке, и занимала
//! место у столбца задержки — того самого, ради которого список читают.
//!
//! Выбранная строка помечена не стрелкой и не чертой сбоку, а одним акцентом:
//! волной, сходящей на нет вправо. Знака в первом столбце здесь быть не может
//! вовсе — ни стрелки, ни полублока: в моноширинном шрифте кита их нет, `iced`
//! берёт такой знак из системного шрифта, а там он шириной в кегль, а не в
//! ячейку, и вся строка съезжает вправо относительно соседних
//! (см. [`crate::console`]). Заливка ничего не занимает в сетке и потому
//! ничего не двигает.
//!
//! Задержка показывается не ради цифры, а ради выбора: из пяти серверов
//! человек берёт ближайший, и «нет ответа» здесь такое же полезное значение,
//! как «42 мс», — оно означает «этот не трогай».

use iced::widget::{Space, button};
use iced::{Alignment, Element, Length};
use penguin_config::schema::profile::Profile;
use penguin_core::id::ProfileId;
use uikit::layout::{Flex, Sizable, Size, gap, px};
use uikit::style::tokens::ink;
use uikit::widgets::ButtonVariant;

use crate::app::TAB_GAP;
use crate::app::message::{Message, ServersMessage};
use crate::app::state::State;
use crate::screens::table::{
    self, BUTTON_HEIGHT, CELL, DASH, ROW_GAP, ROW_PADDING, cell, glyphs, lpad, pad,
};
use crate::ui;

/// Ширина столбца имени в знаках.
///
/// Имя профиля человек придумывает сам и делает коротким; восемнадцати знаков
/// хватает с запасом, а всё, что длиннее, важнее обрезать, чем сдвинуть за
/// ним остальные столбцы.
const NAME_WIDTH: usize = 18;

/// Ширина столбца адреса в знаках.
const SERVER_WIDTH: usize = 26;

/// Ширина столбца протокола в знаках.
///
/// Двенадцать: `hysteria2` — девять, `shadowsocks` — одиннадцать, и столбец
/// заведён с запасом на те, которых ещё нет — имена протоколов короткие, и
/// обрезанное имя перестаёт отвечать на свой единственный вопрос. Обрезка тут
/// всё же есть, но только как страховка от испорченного файла настроек:
/// столбец, съехавший из-за чужой строки в тридцать знаков, ломает таблицу
/// целиком.
const PROTOCOL_WIDTH: usize = 12;

/// Ширина столбца задержки в знаках.
const LATENCY_WIDTH: usize = 8;

/// Ширина столбца действия в точках.
const ACTION_WIDTH: f32 = 76.0;

/// Собирает вкладку целиком: кнопки и панель под ними.
///
/// Вкладка растянута по обеим осям — панель занимает всё, что осталось от
/// кнопок. Страницы с прокруткой вокруг неё нет: прокручивается список внутри
/// панели, а сама панель стоит на месте, как окно терминала.
pub fn view(state: &State) -> Element<'_, Message> {
    Flex::col()
        .w(Size::FILL)
        .h(Size::FILL)
        .push_auto(toolbar(state))
        .push(panel(state))
        // Тот же зазор, что между вкладками и от полосы вкладок до кнопок:
        // одно расстояние на всю вкладку.
        .gap(TAB_GAP)
        .build()
}

/// Две кнопки над панелью.
fn toolbar(state: &State) -> Element<'_, Message> {
    let mut probe =
        ui::button(ButtonVariant::Secondary, crate::i18n::s().probe).h(px(BUTTON_HEIGHT));
    // Пока идёт проверка, повторное нажатие сбросило бы уже собранные
    // задержки и началось бы заново.
    if !state.servers.probing {
        probe = probe.on_press(Message::Servers(ServersMessage::Probe));
    }

    Flex::row()
        .push_auto(
            ui::button(ButtonVariant::Primary, crate::i18n::s().add_server)
                .h(px(BUTTON_HEIGHT))
                .on_press(Message::Servers(ServersMessage::EditorOpened(None))),
        )
        .push_auto(probe)
        .push(ui::spring())
        .gap(gap::SM)
        .align(Alignment::Center)
        .build()
}

/// Панель терминала: таблица на прямоугольнике консоли.
fn panel(state: &State) -> Element<'_, Message> {
    table::panel(
        &state.palette,
        table::search(crate::i18n::s().search, &state.servers.search, |value| {
            Message::Servers(ServersMessage::SearchChanged(value))
        }),
        head(state),
        rows(state),
        crate::i18n::s().select_hint,
    )
}

/// Шапка таблицы — имена столбцов над своими значениями.
fn head(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    let dim = ink::level(&state.palette, ink::TERTIARY);

    let titles = columns(
        glyphs(pad(strings.profile, NAME_WIDTH), dim),
        glyphs(pad(strings.server, SERVER_WIDTH), dim),
        glyphs(pad(strings.protocol, PROTOCOL_WIDTH), dim),
        None,
        glyphs(lpad(strings.latency, LATENCY_WIDTH), dim),
    );

    Flex::row()
        .w(Size::FILL)
        // Тот же отступ, что у строки: заголовок столбца обязан стоять ровно
        // над значениями, а не рядом с ними.
        .push(
            iced::widget::container(titles)
                .padding(ROW_PADDING)
                .width(Length::Fill),
        )
        // Место столбца действия: без него заголовок задержки уехал бы к краю
        // панели, а значения остались бы левее.
        .push_auto(Space::new().width(Length::Fixed(ACTION_WIDTH)))
        .gap(gap::NONE)
        .build()
}

/// Прокручиваемое тело таблицы.
fn rows(state: &State) -> Element<'_, Message> {
    let profiles = &state.config.profiles;
    if profiles.is_empty() {
        return table::empty(&state.palette, crate::i18n::s().no_profiles);
    }

    let shown: Vec<&Profile> = profiles
        .iter()
        .filter(|profile| found(profile, &state.servers.search))
        .collect();
    // Пустой список после поиска — не то же, что пустой список: во втором
    // случае надо добавить сервер, в первом — переписать запрос.
    if shown.is_empty() {
        return table::empty(&state.palette, crate::i18n::s().nothing_found);
    }

    let active = state.config.active().map(|profile| profile.id.clone());
    let list = Flex::col()
        .w(Size::FILL)
        .extend(
            shown
                .into_iter()
                .map(|profile| row(state, profile, active.as_ref())),
        )
        .gap(ROW_GAP)
        .build();

    table::scroll(list)
}

/// Подходит ли профиль под строку поиска.
///
/// Свободная функция с тестом: искать по одному только имени мало — сервер
/// вспоминают и по адресу, и по протоколу.
fn found(profile: &Profile, query: &str) -> bool {
    let server = crate::screens::servers::server_of(profile).unwrap_or_default();

    table::matches(
        query,
        &[
            &profile.name,
            profile.id.as_str(),
            server,
            &profile.outbound.protocol,
        ],
    )
}

/// Строка профиля: сама строка выбирает, кнопка справа открывает правку.
fn row<'a>(
    state: &'a State,
    profile: &'a Profile,
    active: Option<&ProfileId>,
) -> Element<'a, Message> {
    let id = profile.id.to_string();
    let selected = active == Some(&profile.id);
    let palette = &state.palette;

    // Выбранный ярче остальных: список читают ради вопроса «какой сейчас», и
    // ответ на него должен находиться боковым зрением.
    let (name_ink, server_ink) = if selected {
        (palette.text, ink::level(palette, ink::SECONDARY))
    } else {
        (
            ink::level(palette, ink::SECONDARY),
            ink::level(palette, ink::TERTIARY),
        )
    };
    // Протокол тише адреса в любой строке: его читают, когда протоколов в
    // списке несколько, а не когда выбирают сервер.
    let protocol_ink = ink::level(palette, ink::TERTIARY);
    let managed = profile.is_managed().then(|| {
        // Правки в таком профиле пропадут при обновлении подписки.
        glyphs(
            crate::i18n::s().managed.to_owned(),
            ink::level(palette, ink::TERTIARY),
        )
    });

    let server = crate::screens::servers::server_of(profile)
        .map_or_else(|| DASH.to_string(), |server| cell(server, SERVER_WIDTH));

    let cells = columns(
        glyphs(cell(&profile.name, NAME_WIDTH), name_ink),
        glyphs(pad(&server, SERVER_WIDTH), server_ink),
        glyphs(
            cell(&profile.outbound.protocol, PROTOCOL_WIDTH),
            protocol_ink,
        ),
        managed,
        glyphs(
            lpad(&latency(state, &profile.id), LATENCY_WIDTH),
            ink::level(palette, ink::SECONDARY),
        ),
    );

    let mut select = button(cells)
        .width(Length::Fill)
        .padding(ROW_PADDING)
        .style(table::row_style(selected));
    // Выбранную строку выбирать некуда: нажатие без последствий читается как
    // сломанное.
    if !selected {
        select = select.on_press(Message::Servers(ServersMessage::Select(id.clone())));
    }

    Flex::row()
        .push(select)
        .push_auto(table::action(
            crate::i18n::s().edit,
            ACTION_WIDTH,
            Message::Servers(ServersMessage::EditorOpened(Some(id))),
        ))
        .gap(gap::NONE)
        .align(Alignment::Center)
        .build()
}

/// Ряд ячеек таблицы — один на шапку и на строки.
///
/// Общий, потому что столбец, съехавший на знак, — единственное, что видно в
/// таблице, а два похожих ряда рядом расходятся сами собой.
fn columns<'a, Message: 'a>(
    name: Element<'a, Message>,
    server: Element<'a, Message>,
    protocol: Element<'a, Message>,
    managed: Option<Element<'a, Message>>,
    latency: Element<'a, Message>,
) -> Element<'a, Message> {
    let mut line = Flex::row()
        .w(Size::FILL)
        .push_auto(name)
        .push_auto(server)
        .push_auto(protocol);

    // Метка подписки стоит **до** распорки: за ней столбец задержки съезжал бы
    // влево ровно на тех строках, где она есть.
    if let Some(managed) = managed {
        line = line.push_auto(managed);
    }

    line.push(ui::spring())
        .push_auto(latency)
        .gap(CELL)
        .align(Alignment::Center)
        .build()
}

/// Задержка до сервера словом или цифрой.
fn latency(state: &State, id: &ProfileId) -> String {
    let strings = crate::i18n::s();
    if state.servers.probing {
        return strings.probing.to_owned();
    }

    state
        .servers
        .latencies
        .iter()
        .find(|(profile, _)| profile == id.as_str())
        .map_or_else(
            || DASH.to_string(),
            |(_, rtt)| match rtt {
                Some(rtt) => format!("{rtt} {}", strings.millis),
                // «Нет ответа» — это тоже ответ: он означает «этот не трогай».
                None => strings.no_answer.to_owned(),
            },
        )
}

#[cfg(test)]
mod tests {
    use iced::Color;
    use penguin_config::schema::outbound::RawOutbound;
    use serde_json::json;

    use super::*;

    fn profile(name: &str) -> Profile {
        Profile::new(
            name,
            name,
            RawOutbound::new("hysteria2", json!({ "server": "example.com:443" })),
        )
    }

    #[test]
    fn an_empty_list_says_so() {
        // Пустая рамка читается как «не загрузилось».
        let state = State::default();
        assert!(state.config.profiles.is_empty());
        let _ = view(&state);
    }

    #[test]
    fn the_tab_fills_the_panel() {
        // Панель — окно терминала: она занимает вкладку целиком, а
        // прокручивается список внутри неё.
        let mut state = State::default();
        state.config.profiles.push(profile("home"));

        let size = view(&state).as_widget().size();
        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn columns_keep_their_width() {
        // Таблицу читают по столбцам; съехавший на знак столбец рушит весь
        // смысл затеи.
        assert_eq!(pad("source", NAME_WIDTH).chars().count(), NAME_WIDTH);
        assert_eq!(
            cell("hysteria2", PROTOCOL_WIDTH).chars().count(),
            PROTOCOL_WIDTH
        );
        assert_eq!(lpad("90 мс", LATENCY_WIDTH).chars().count(), LATENCY_WIDTH);
    }

    #[test]
    fn the_chosen_row_never_shifts_its_columns() {
        // Знак-метка в первом столбце сдвигал бы выбранную строку относительно
        // соседних: в шрифте кита его нет, и системный рисует его шириной в
        // кегль, а не в ячейку.
        let dim = Color::WHITE;
        let head: Element<'_, Message> = columns(
            glyphs(pad("ПРОФИЛЬ", NAME_WIDTH), dim),
            glyphs(pad("СЕРВЕР", SERVER_WIDTH), dim),
            glyphs(pad("ПРОТОКОЛ", PROTOCOL_WIDTH), dim),
            None,
            glyphs(lpad("ЗАДЕРЖКА", LATENCY_WIDTH), dim),
        );
        let row: Element<'_, Message> = columns(
            glyphs(pad("source", NAME_WIDTH), dim),
            glyphs(pad("example.com:443", SERVER_WIDTH), dim),
            glyphs(pad("hysteria2", PROTOCOL_WIDTH), dim),
            None,
            glyphs(lpad("42 мс", LATENCY_WIDTH), dim),
        );

        assert_eq!(head.as_widget().size(), row.as_widget().size());
    }

    #[test]
    fn the_chosen_row_is_marked_and_the_rest_are_not() {
        let mut state = State::default();
        state.config.profiles.push(profile("home"));
        state.config.profiles.push(profile("work"));
        state.config.active_profile = Some(ProfileId::new("work"));

        let _ = view(&state);
    }

    #[test]
    fn search_finds_a_profile_by_any_of_its_columns() {
        // Сервер вспоминают то по имени, то по адресу, то по протоколу.
        let profile = profile("home");
        assert!(found(&profile, ""));
        assert!(found(&profile, "HOME"));
        assert!(found(&profile, "example.com"));
        assert!(found(&profile, "hysteria"));
        assert!(!found(&profile, "нет такого"));
    }

    #[test]
    fn a_search_that_finds_nothing_says_so() {
        // «Ничего не нашлось» и «профилей нет» требуют разных действий: в
        // одном случае переписать запрос, в другом — добавить сервер.
        let mut state = State::default();
        state.config.profiles.push(profile("home"));
        state.servers.search = "нет такого".to_owned();
        let _ = view(&state);
    }

    #[test]
    fn the_protocol_column_holds_the_names_that_are_coming() {
        // Столбец заведён под протоколы, которых ещё нет; обрезанное имя
        // протокола перестаёт отвечать на свой единственный вопрос.
        for protocol in ["hysteria2", "shadowsocks", "wireguard", "vless"] {
            assert!(
                protocol.chars().count() <= PROTOCOL_WIDTH,
                "`{protocol}` не помещается в столбец"
            );
        }
    }

    #[test]
    fn a_profile_without_an_address_shows_a_dash_not_its_protocol() {
        // Иначе одно и то же значение стояло бы в двух соседних клетках.
        let profile = Profile::new("x", "x", RawOutbound::new("vless", json!({})));
        assert_eq!(crate::screens::servers::server_of(&profile), None);
    }

    #[test]
    fn a_probe_in_flight_shows_itself_in_every_row() {
        // Пустая клетка во время проверки читается как «не ответил».
        let mut state = State::default();
        state.config.profiles.push(profile("home"));
        state.servers.probing = true;

        assert_eq!(
            latency(&state, &ProfileId::new("home")),
            crate::i18n::s().probing
        );
    }

    #[test]
    fn no_answer_is_a_value_too() {
        // Оно означает «этот не трогай» и полезно ровно так же, как цифра.
        let mut state = State::default();
        state.servers.latencies.push(("home".to_owned(), None));

        assert_eq!(
            latency(&state, &ProfileId::new("home")),
            crate::i18n::s().no_answer
        );
    }

    #[test]
    fn an_unknown_latency_is_a_dash_the_font_has() {
        // Длинного тире в моноширинном шрифте может не быть, и тогда оно
        // занимает не свою ячейку — столбец съезжает.
        let state = State::default();
        assert_eq!(latency(&state, &ProfileId::new("home")), DASH.to_string());
    }
}
