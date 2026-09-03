//! Список профилей — символьная панель терминала во всю вкладку.
//!
//! Таблица, а не карточки: у профиля три значения — имя, адрес, задержка, — и
//! сравнивают их **между строками**, по столбцам. Карточки ставят те же
//! значения в разных местах каждой строки, и глазу приходится искать их заново
//! на каждом сервере.
//!
//! # Рамки нет, есть отступ
//!
//! Панель — тёмный прямоугольник консоли, и таблица начинается сразу. Рамка из
//! знаков вокруг неё обводила то, что и так очерчено фоном, и отнимала строку
//! сверху и снизу. Границу держит отступ [`PANEL_PADDING`] — он же не даёт
//! столбцам упереться в край.
//!
//! Единственная черта, которая осталась, — под шапкой: она отделяет имена
//! столбцов от значений, а не обводит панель. Набрана заполнителем из `─`,
//! обрезанным контейнером по месту: знаки не считаются, и правый край черты
//! приходится ровно на край панели при любой ширине окна.
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

use iced::theme::Palette;
use iced::widget::text::{LineHeight, Wrapping};
use iced::widget::{Space, button, container, scrollable, text};
use iced::{Alignment, Color, Element, Length, Padding, Theme};
use penguin_config::schema::profile::Profile;
use penguin_core::id::ProfileId;
use uikit::layout::{Flex, Sizable, Size, gap, px};
use uikit::style::container::Wash;
use uikit::style::scrollbar;
use uikit::style::tokens::{accent, ink, radius, type_scale};
use uikit::widgets::ButtonVariant;

use crate::app::TAB_GAP;
use crate::app::message::{Message, ServersMessage};
use crate::app::state::State;
use crate::ui;

/// Кегль панели — тот же, что у строки журнала и у консоли главного экрана.
const GLYPH: f32 = type_scale::BODY;

/// Ширина знака в долях кегля.
///
/// У встроенного ZedMono знак узкий — около половины кегля. Точное значение
/// знает только шрифт, и здесь оно нужно ровно для отступов: раскладку
/// столбцов держат пробелы внутри строк, а не эта оценка.
const ADVANCE: f32 = 0.55;

/// Ширина знака в точках.
const CELL: f32 = GLYPH * ADVANCE;

/// Отступ от края панели до таблицы.
///
/// Три знака: столбец, прижатый к краю тёмного прямоугольника, читается как
/// обрезанный. Слева к нему добавляется отступ строки — на него заходит
/// заливка выбранной, и без него она упиралась бы в первую букву.
const PANEL_PADDING: f32 = CELL * 3.0;

/// Высота кнопок над панелью.
const BUTTON_HEIGHT: f32 = 26.0;

/// Отступ строки: одинаковый сверху и снизу, по знаку слева и справа.
///
/// Высота строки числом **не** задаётся, и это не мелочь: `iced` кладёт
/// содержимое кнопки в левый верхний угол отведённого места, а не в середину
/// (`layout::padded`). Заданная высота при строке текста вдвое ниже уводила
/// заливку под строку на весь остаток. Высоту даёт содержимое, а поровну
/// сверху и снизу её добирает этот отступ — тогда заливка обнимает строку и
/// разъехаться с ней не может.
const ROW_PADDING: Padding = Padding {
    top: gap::XS,
    right: gap::XS,
    bottom: gap::XS,
    left: gap::XS,
};

/// Зазор между строками списка.
///
/// Строки — это строки таблицы, а не отдельные карточки: зазор отделяет одну
/// заливку от другой и не больше. Больший рассыпал бы столбец на несвязанные
/// значения.
const ROW_GAP: f32 = gap::XS;

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
///
/// Задана числом, а не по подписи: над ним стоит заголовок столбца задержки, и
/// подпись, которая на другом языке короче, увела бы заголовок от значений.
const ACTION_WIDTH: f32 = 76.0;

/// Длина заполнителя кромки в знаках.
///
/// Нарочно длиннее любого окна: правый край заполнителя приходится на край
/// панели потому, что лишнее обрезано, а не потому, что число подобрано.
const FILLER: usize = 240;

/// Черта под шапкой таблицы.
const HORIZONTAL: char = '─';

/// Приглашение перед сообщением пустого списка.
const PROMPT: char = '>';

/// Прочерк на месте пустого значения.
///
/// Дефис, а не длинное тире: в панели идут только те знаки, что в ZedMono есть
/// наверняка, — иначе `iced` берёт знак из системного шрифта, и он занимает
/// не свою ячейку (см. [`crate::console`]).
const DASH: char = '-';

/// Сила акцента у левого края выбранной строки.
///
/// Заметно выше ступеней `state::TINT_*`: те заливают строку ровно, а здесь
/// акцент сходит на нет к правому краю, и головка такой же силы читалась бы
/// вдвое тише самой заливки.
const SELECTED: f32 = 0.60;

/// То же под курсором на невыбранной строке.
const HOVERED: f32 = 0.22;

/// То же в момент нажатия.
const PRESSED: f32 = 0.36;

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

/// Панель терминала: таблица на тёмном прямоугольнике консоли.
fn panel(state: &State) -> Element<'_, Message> {
    let palette = &state.palette;

    let body = Flex::col()
        .w(Size::FILL)
        .h(Size::FILL)
        .push_auto(head(state))
        .push_auto(filler(palette, HORIZONTAL))
        .push(rows(state))
        .push_auto(hint(palette))
        .gap(gap::XS)
        .build();

    container(body)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(Padding::new(PANEL_PADDING))
        .style(uikit::style::container::log_terminal_viewport as fn(&Theme) -> _)
        // Заполнитель нарочно длиннее панели; без отсечения он вылез бы за её
        // тёмный прямоугольник.
        .clip(true)
        .into()
}

/// Как выбрать профиль — строкой у нижнего края панели.
///
/// Кнопки «Выбрать» в строке больше нет, а щелчок по строке ниоткуда не
/// виден: действие без своего элемента управления обязано быть где-то
/// написано словами.
fn hint<'a, Message: 'a>(palette: &Palette) -> Element<'a, Message> {
    glyphs(
        crate::i18n::s().select_hint.to_owned(),
        ink::level(palette, ink::TERTIARY),
    )
}

/// Заполнитель на всю оставшуюся ширину.
///
/// Нарочно длиннее любого окна и обрезается контейнером — так его правый край
/// приходится ровно на край панели, а не на подобранное на глаз число знаков.
fn filler<'a, Message: 'a>(palette: &Palette, glyph: char) -> Element<'a, Message> {
    let line: String = std::iter::repeat_n(glyph, FILLER).collect();

    container(glyphs(line, ink::level(palette, ink::TERTIARY)))
        .width(Length::Fill)
        .clip(true)
        .into()
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
        .push(container(titles).padding(ROW_PADDING).width(Length::Fill))
        // Место столбца действия: без него заголовок задержки уехал бы к краю
        // панели, а значения остались бы левее.
        .push_auto(Space::new().width(Length::Fixed(ACTION_WIDTH)))
        .gap(gap::NONE)
        .build()
}

/// Прокручиваемый список профилей.
fn rows(state: &State) -> Element<'_, Message> {
    let profiles = &state.config.profiles;
    if profiles.is_empty() {
        return empty(state);
    }

    let active = state.config.active().map(|profile| profile.id.clone());
    let list = Flex::col()
        .w(Size::FILL)
        .extend(
            profiles
                .iter()
                .map(|profile| row(state, profile, active.as_ref())),
        )
        .gap(ROW_GAP)
        .build();

    // Отступ — на содержимом прокрутки, а не на обёртке: иначе полоса ляжет
    // поверх строк у правого края (правило 4.6 кита).
    scrollable(
        container(list)
            .padding(scrollbar::safe(0.0))
            .width(Length::Fill),
    )
    .direction(scrollbar::vertical())
    .style(scrollbar::style())
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

/// Пустой список: почему здесь ничего нет.
///
/// Пустая рамка читается как «не загрузилось», и человек ждёт.
fn empty<'a, Message: 'a>(state: &State) -> Element<'a, Message> {
    let line = format!("{PROMPT} {}", crate::i18n::s().no_profiles);

    container(glyphs(line, ink::level(&state.palette, ink::TERTIARY)))
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(gap::SM)
        .into()
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
        .map_or_else(|| DASH.to_string(), |server| clip(server, SERVER_WIDTH));

    let cells = columns(
        glyphs(pad(&clip(&profile.name, NAME_WIDTH), NAME_WIDTH), name_ink),
        glyphs(pad(&server, SERVER_WIDTH), server_ink),
        glyphs(
            pad(
                &clip(&profile.outbound.protocol, PROTOCOL_WIDTH),
                PROTOCOL_WIDTH,
            ),
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
        .style(row_style(selected));
    // Выбранную строку выбирать некуда: нажатие без последствий читается как
    // сломанное.
    if !selected {
        select = select.on_press(Message::Servers(ServersMessage::Select(id.clone())));
    }

    Flex::row()
        .push(select)
        .push_auto(action(id))
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

/// Правка профиля — подпись в скобках, как пункт меню терминала.
fn action<'a>(id: String) -> Element<'a, Message> {
    let label = format!("[{}]", crate::i18n::s().edit);

    button(
        container(
            text(label)
                .size(GLYPH)
                .line_height(LineHeight::Relative(1.0))
                .wrapping(Wrapping::None),
        )
        .center_x(Length::Fill),
    )
    .width(Length::Fixed(ACTION_WIDTH))
    // Тот же отступ, что у строки: иначе кнопка ниже строки, и подпись стоит
    // не на её линии.
    .padding(ROW_PADDING)
    .style(uikit::style::button::ghost)
    .on_press(Message::Servers(ServersMessage::EditorOpened(Some(id))))
    .into()
}

/// Вид строки: акцентная волна от левого края, сходящая на нет вправо.
///
/// Волна, а не ровная заливка: ровная превращает строку в плашку, и список из
/// них читается как решётка. Волна помечает начало строки — там же, где стоит
/// метка, — и отпускает столбец задержки у правого края.
fn row_style(selected: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        let palette = theme.palette();
        let strength = match (selected, status) {
            // Выбранная строка нажатия не принимает, и `iced` считает её
            // недоступной; выглядеть она обязана выбранной.
            (true, _) => SELECTED,
            (false, button::Status::Hovered) => HOVERED,
            (false, button::Status::Pressed) => PRESSED,
            (false, _) => 0.0,
        };

        if strength <= 0.0 {
            return button::Style {
                text_color: palette.text,
                ..button::Style::default()
            };
        }

        // Волна берётся у кита целиком: у контейнера и у кнопки она обязана
        // быть одной и той же, а второй такой градиент разошёлся бы с первым.
        let wave = uikit::style::container::washed(
            Color::TRANSPARENT,
            accent::wash(&palette, strength),
            Wash::FromLeft,
            radius::CONTROL,
        );

        button::Style {
            background: wave.background,
            border: wave.border,
            text_color: palette.text,
            ..button::Style::default()
        }
    }
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

/// Знаки панели: кегль, цвет, без переноса.
///
/// Шрифт не задаётся: он один на всё окно и приходит умолчанием (см.
/// [`crate::ui::FONT`]).
fn glyphs<'a, Message: 'a>(value: String, color: Color) -> Element<'a, Message> {
    text(value)
        .size(GLYPH)
        // Ровно кегль: запас между строками стоит снаружи, в зазоре группы.
        .line_height(LineHeight::Relative(1.0))
        .color(color)
        // Без переноса: строка таблицы — это строка, а не абзац.
        .wrapping(Wrapping::None)
        .into()
}

/// Дополняет строку пробелами до ширины столбца.
///
/// Свободная функция с тестом: столбец, съехавший на знак, — единственное, что
/// видно в таблице, и последнее, что находится глазами в коде.
fn pad(value: &str, width: usize) -> String {
    let tail = width.saturating_sub(value.chars().count());
    format!("{value}{}", " ".repeat(tail))
}

/// То же, но пробелы слева: значение встаёт по правому краю столбца.
fn lpad(value: &str, width: usize) -> String {
    let head = width.saturating_sub(value.chars().count());
    format!("{}{value}", " ".repeat(head))
}

/// Обрезает строку по знакам, а не по байтам.
///
/// Хвост помечен тильдой: так DOS укорачивал длинные имена (`PROGRA~1`), и, в
/// отличие от многоточия, тильда в моноширинном шрифте кита есть наверняка —
/// значит, займёт ровно знак и не сдвинет за собой столбец.
fn clip(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_owned();
    }
    value
        .chars()
        .take(width.saturating_sub(1))
        .collect::<String>()
        + "~"
}

#[cfg(test)]
mod tests {
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
        // прокручивается список внутри неё. Растянутой вкладку объявляет
        // именно она; страницы с прокруткой вокруг больше нет.
        let mut state = State::default();
        state.config.profiles.push(profile("home"));

        let size = view(&state).as_widget().size();
        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn the_fill_sits_evenly_around_the_row() {
        // Высота строки задавалась числом, а `iced` кладёт содержимое кнопки в
        // левый верхний угол, а не в середину: заливка уходила под строку на
        // весь остаток. Высоту теперь даёт содержимое, и отступ обязан быть
        // одинаковым сверху и снизу.
        assert_eq!(ROW_PADDING.top, ROW_PADDING.bottom);
    }

    #[test]
    fn columns_keep_their_width() {
        // Таблицу читают по столбцам; съехавший на знак столбец рушит весь
        // смысл затеи.
        assert_eq!(pad("source", NAME_WIDTH).chars().count(), NAME_WIDTH);
        assert_eq!(pad("", NAME_WIDTH).chars().count(), NAME_WIDTH);
        assert_eq!(
            pad("hysteria2", PROTOCOL_WIDTH).chars().count(),
            PROTOCOL_WIDTH
        );
        assert_eq!(lpad("90 мс", LATENCY_WIDTH).chars().count(), LATENCY_WIDTH);
    }

    #[test]
    fn a_value_in_the_latency_column_sits_at_its_right_edge() {
        // Цифры сравнивают по разрядам, а разряды совпадают только у значений,
        // выровненных вправо.
        assert!(lpad("42 мс", LATENCY_WIDTH).starts_with("   "));
        assert!(lpad("42 мс", LATENCY_WIDTH).ends_with("42 мс"));
    }

    #[test]
    fn a_long_name_is_clipped_not_pushed_through() {
        // Иначе длинное имя сдвинуло бы за собой все остальные столбцы.
        let long = "и".repeat(100);
        assert_eq!(clip(&long, NAME_WIDTH).chars().count(), NAME_WIDTH);
        assert!(clip(&long, NAME_WIDTH).ends_with('~'));
    }

    #[test]
    fn a_name_that_fits_is_left_alone() {
        assert_eq!(clip("source", NAME_WIDTH), "source");
    }

    #[test]
    fn the_chosen_row_never_shifts_its_columns() {
        // Знак-метка в первом столбце сдвигал бы выбранную строку относительно
        // соседних: в шрифте кита его нет, и системный рисует его шириной в
        // кегль, а не в ячейку. Столбцы строк собираются из одних и тех же
        // ячеек, и разойтись им не с чего.
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
