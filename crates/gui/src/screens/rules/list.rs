//! Вкладка правил: режим, кнопки, таблица.
//!
//! Устроена так же, как вкладка серверов, и той же таблицей
//! ([`crate::screens::table`]). Причина не в единообразии ради единообразия: у
//! правила, как и у профиля, несколько значений, и сравнивают их **между
//! строками** — какое из тридцати правил перехватит это соединение первым.
//! Карточки ставят те же значения в разных местах каждой строки, и глазу
//! приходится искать их заново на каждом правиле.
//!
//! Порядок сверху вниз повторяет порядок решений:
//!
//! 1. **режим** — что происходит с трафиком, о котором не сказано ничего;
//! 2. **кнопки** — чем этот набор пополнить и как его проверить;
//! 3. **таблица** — что уже есть.
//!
//! Форма нового правила и проверка живут в модальных окнах, а не разделами под
//! таблицей. Форма из девяти полей и список приложений в полторы сотни строк
//! отодвигали таблицу за нижний край окна, и человек писал правило, не видя
//! тех, что уже есть, — тогда как новое правило почти всегда пишут, глядя на
//! соседнее. По той же причине у вкладки нет своей прокрутки: наружу не
//! уезжает ничего, а прокручивается тело таблицы внутри панели.
//!
//! # Что в строке
//!
//! Имя, условие словами и действие. Условие — главный столбец: имя правило
//! получает от человека и через месяц оно значит для него что угодно, а
//! условие отвечает на единственный вопрос, ради которого таблицу и открыли,
//! — **какое соединение это правило заберёт**. Описывается оно тем же кодом,
//! что и в проверке, чтобы таблица и объяснение не разошлись.
//!
//! Выключенное правило не спрятано и не вычеркнуто: оно приглушено целиком и
//! помечено словом. Вычеркнутая строка в моноширинной таблице требует знака,
//! которого в шрифте кита нет, а спрятанное правило человек ищет и не находит.

use iced::widget::button;
use iced::{Alignment, Element, Length};
use penguin_config::schema::rule::{Condition, Leaf, RuleAction, RuleConfig};
use uikit::layout::{Flex, Sizable, Size, gap, px};
use uikit::style::tokens::ink;
use uikit::widgets::ButtonVariant;

use crate::app::TAB_GAP;
use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::screens::rules::mode;
use crate::screens::table::{
    self, BUTTON_HEIGHT, CELL, ROW_GAP, ROW_PADDING, cell, glyphs, lpad, pad,
};
use crate::ui;

/// Ширина столбца имени в знаках.
///
/// Имя придумывает человек и делает коротким; всё, что длиннее, важнее
/// обрезать, чем сдвинуть за ним столбец условия.
const NAME_WIDTH: usize = 20;

/// Ширина столбца условия в знаках.
///
/// Самый широкий столбец таблицы, и намеренно: условие — то, ради чего её
/// открыли. Описание всё равно бывает длиннее, но обрезанное «приложение:
/// steam.exe и домен...» отвечает на вопрос, а не влезшее целиком — уже нет.
const CONDITION_WIDTH: usize = 46;

/// Ширина столбца действия в знаках.
///
/// Шире самой длинной подписи: «в тоннель» может прийти с именем профиля
/// (`в тоннель -> office`), и столбец, съехавший на таких строках, ломает
/// таблицу целиком.
const ACTION_WIDTH: usize = 20;

/// Ширина кнопки удаления в точках.
const REMOVE_WIDTH: f32 = 76.0;

/// Собирает вкладку целиком.
pub fn view(state: &State) -> Element<'_, Message> {
    Flex::col()
        .w(Size::FILL)
        .h(Size::FILL)
        .push_auto(mode::view(state))
        .push_auto(toolbar(state))
        .push(panel(state))
        // Тот же зазор, что между вкладками и что на вкладке серверов: одно
        // расстояние на всё окно.
        .gap(TAB_GAP)
        .build()
}

/// Кнопки над таблицей.
///
/// «Сохранить» появляется только при несохранённых правках и стоит у правого
/// края, отдельно от двух остальных: постоянно видимая, она перестаёт
/// что-либо значить, и её жмут на всякий случай.
///
/// Набрана акцентом темы, а не зелёным «получилось»: зелёный в ките означает
/// исход, о котором сообщают, а тут — действие, которое предлагают. Двух
/// акцентных кнопок в ряду это не создаёт: пока правок нет, её нет вовсе, а
/// появившись, она стоит у другого края.
fn toolbar(state: &State) -> Element<'_, Message> {
    let mut row = Flex::row()
        .push_auto(
            ui::button(ButtonVariant::Primary, crate::i18n::s().add_rule)
                .h(px(BUTTON_HEIGHT))
                .on_press(Message::SplitTunnel(SplitTunnelMessage::EditorOpened)),
        )
        .push_auto(
            ui::button(ButtonVariant::Secondary, crate::i18n::s().probe_rule)
                .h(px(BUTTON_HEIGHT))
                .on_press(Message::SplitTunnel(SplitTunnelMessage::ProbeOpened)),
        )
        .push(ui::spring());

    if state.dirty {
        row = row.push_auto(
            ui::button(ButtonVariant::Primary, crate::i18n::s().save)
                .h(px(BUTTON_HEIGHT))
                .on_press(Message::SplitTunnel(SplitTunnelMessage::Save)),
        );
    }

    row.gap(gap::SM).align(Alignment::Center).build()
}

/// Панель терминала: таблица правил.
fn panel(state: &State) -> Element<'_, Message> {
    table::panel(
        &state.palette,
        table::search(
            crate::i18n::s().search,
            &state.split_tunnel.search,
            |value| Message::SplitTunnel(SplitTunnelMessage::SearchChanged(value)),
        ),
        head(state),
        rows(state),
        crate::i18n::s().toggle_hint,
    )
}

/// Шапка таблицы — имена столбцов над своими значениями.
fn head(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    let dim = ink::level(&state.palette, ink::TERTIARY);

    let titles = columns(
        glyphs(pad(strings.rule, NAME_WIDTH), dim),
        glyphs(pad(strings.condition, CONDITION_WIDTH), dim),
        None,
        glyphs(lpad(strings.action, ACTION_WIDTH), dim),
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
        // Место столбца удаления: без него заголовок действия уехал бы к краю
        // панели, а значения остались бы левее.
        .push_auto(iced::widget::Space::new().width(Length::Fixed(REMOVE_WIDTH)))
        .gap(gap::NONE)
        .build()
}

/// Прокручиваемое тело таблицы.
fn rows(state: &State) -> Element<'_, Message> {
    let rules = &state.config.routing.rules;
    if rules.is_empty() {
        return table::empty(&state.palette, crate::i18n::s().no_rules);
    }

    // Место правила в наборе — это его приоритет, и оно уезжает в сообщение об
    // удалении. Поэтому номер берётся до отбора: после поиска второе правило
    // стало бы первым, и удалилось бы не то.
    let shown: Vec<(usize, &RuleConfig)> = rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| found(rule, &state.split_tunnel.search))
        .collect();
    // Пустой список после поиска — не то же, что пустой набор: в одном случае
    // надо переписать запрос, в другом — добавить правило.
    if shown.is_empty() {
        return table::empty(&state.palette, crate::i18n::s().nothing_found);
    }

    let list = Flex::col()
        .w(Size::FILL)
        .extend(
            shown
                .into_iter()
                .map(|(index, rule)| row(state, index, rule)),
        )
        .gap(ROW_GAP)
        .build();

    table::scroll(list)
}

/// Подходит ли правило под строку поиска.
///
/// Ищет и по имени, и по условию, и по действию: правило вспоминают то по
/// названию, то по приложению, которое в него вписали.
fn found(rule: &RuleConfig, query: &str) -> bool {
    let condition = describe_condition(&rule.when);
    let action = describe_action(&rule.action);

    table::matches(query, &[&rule.name, &rule.id, &condition, &action])
}

/// Строка правила: щелчок включает и выключает, кнопка справа удаляет.
fn row<'a>(state: &'a State, index: usize, rule: &'a RuleConfig) -> Element<'a, Message> {
    let palette = &state.palette;
    let action = describe_action(&rule.action);

    // Выключенное правило приглушено целиком: оно ничего не делает, и читать
    // его наравне с работающими незачем. Но оно на месте — спрятанное правило
    // человек ищет и не находит.
    let (name_ink, condition_ink, action_ink) = if rule.enabled {
        (
            palette.text,
            ink::level(palette, ink::SECONDARY),
            ink::level(palette, ink::SECONDARY),
        )
    } else {
        let faint = ink::level(palette, ink::TERTIARY);
        (faint, faint, faint)
    };

    let name = if rule.name.trim().is_empty() {
        rule.id.clone()
    } else {
        rule.name.clone()
    };
    let off = (!rule.enabled).then(|| {
        glyphs(
            crate::i18n::s().rule_off.to_owned(),
            ink::level(palette, ink::TERTIARY),
        )
    });

    let cells = columns(
        glyphs(cell(&name, NAME_WIDTH), name_ink),
        glyphs(
            cell(&describe_condition(&rule.when), CONDITION_WIDTH),
            condition_ink,
        ),
        off,
        glyphs(
            lpad(&table::clip(&action, ACTION_WIDTH), ACTION_WIDTH),
            action_ink,
        ),
    );

    let toggle = button(cells)
        .width(Length::Fill)
        .padding(ROW_PADDING)
        // Волна помечает включённое правило: список читают ради вопроса
        // «какие сейчас работают», и ответ должен находиться боковым зрением.
        .style(table::row_style(rule.enabled))
        .on_press(Message::SplitTunnel(SplitTunnelMessage::RuleToggled(
            index,
            !rule.enabled,
        )));

    Flex::row()
        .push(toggle)
        .push_auto(table::action(
            crate::i18n::s().remove,
            REMOVE_WIDTH,
            Message::SplitTunnel(SplitTunnelMessage::RuleRemoved(index)),
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
    condition: Element<'a, Message>,
    off: Option<Element<'a, Message>>,
    action: Element<'a, Message>,
) -> Element<'a, Message> {
    let mut line = Flex::row()
        .w(Size::FILL)
        .push_auto(name)
        .push_auto(condition);

    // Метка «выкл» стоит **до** распорки: за ней столбец действия съезжал бы
    // влево ровно на тех строках, где она есть.
    if let Some(off) = off {
        line = line.push_auto(off);
    }

    line.push(ui::spring())
        .push_auto(action)
        .gap(CELL)
        .align(Alignment::Center)
        .build()
}

/// Подпись действия.
///
/// Стрелка набрана из дефиса и уголка, а не знаком `→`: в таблице идут только
/// те знаки, что в ZedMono есть наверняка, — иначе `iced` берёт знак из
/// системного шрифта, и он занимает не свою ячейку (см. [`crate::console`]).
pub fn describe_action(action: &RuleAction) -> String {
    match action {
        RuleAction::Tunnel {
            profile: Some(profile),
        } => format!("{} -> {profile}", crate::i18n::s().action_tunnel),
        RuleAction::Tunnel { profile: None } => crate::i18n::s().action_tunnel.to_owned(),
        RuleAction::Direct => crate::i18n::s().action_direct.to_owned(),
        RuleAction::Block => crate::i18n::s().action_block.to_owned(),
    }
}

/// Описывает условие словами.
///
/// Короче, чем описание в проверке правил: в таблице важно узнать правило, а
/// не разобрать его целиком. Полное описание показывает окно проверки.
pub fn describe_condition(condition: &Condition) -> String {
    match condition {
        Condition::All { all } => all
            .iter()
            .map(describe_condition)
            .collect::<Vec<_>>()
            .join(" и "),
        Condition::Any { any } => any
            .iter()
            .map(describe_condition)
            .collect::<Vec<_>>()
            .join(" или "),
        Condition::Not { not } => format!("не {}", describe_condition(not)),
        Condition::Leaf(leaf) => describe_leaf(leaf),
    }
}

/// Описывает элементарное условие.
fn describe_leaf(leaf: &Leaf) -> String {
    /// Список значений, обрезанный до читаемой длины.
    ///
    /// Двадцать отмеченных приложений в одной строке превращают таблицу правил
    /// в стену текста.
    fn short(values: &[String]) -> String {
        const SHOWN: usize = 3;

        if values.len() <= SHOWN {
            return values.join(", ");
        }
        format!(
            "{}, ещё {}",
            values[..SHOWN].join(", "),
            values.len() - SHOWN
        )
    }

    fn short_ports(values: &[u16]) -> String {
        short(&values.iter().map(u16::to_string).collect::<Vec<_>>())
    }

    match leaf {
        Leaf::ProcessPath(values) => format!("путь: {}", short(values)),
        Leaf::ProcessName(values) => format!("приложение: {}", short(values)),
        Leaf::ProcessPathGlob(values) => format!("путь по маске: {}", short(values)),
        Leaf::Domain(values) => format!("домен: {}", short(values)),
        Leaf::DomainSuffix(values) => format!("домен и поддомены: {}", short(values)),
        Leaf::DomainKeyword(values) => format!("домен содержит: {}", short(values)),
        Leaf::DomainRegex(values) => format!("домен по выражению: {}", short(values)),
        Leaf::DestIp(values) => format!("адрес: {}", short(values)),
        Leaf::DestPort(values) => format!("порт: {}", short_ports(values)),
        Leaf::DestPortRange(values) => {
            let ranges: Vec<String> = values
                .iter()
                .map(|(from, to)| format!("{from}-{to}"))
                .collect();
            format!("порты: {}", short(&ranges))
        }
        Leaf::GeoIp(values) => format!("страна: {}", short(values)),
        Leaf::GeoSite(values) => format!("набор доменов: {}", short(values)),
        Leaf::Network(values) => format!("трафик: {}", short(values)),
        Leaf::IpVersion(values) => format!("версия IP: {}", short(values)),
    }
}

#[cfg(test)]
mod tests {
    use iced::Color;
    use serde_json::json;

    use super::*;

    fn condition(value: serde_json::Value) -> Condition {
        serde_json::from_value(value).expect("условие разбирается")
    }

    fn state_with_rules(rules: serde_json::Value) -> State {
        let mut state = State::default();
        state.config.routing.rules = serde_json::from_value(rules).expect("правила разбираются");
        state
    }

    #[test]
    fn the_tab_fills_the_window() {
        // Прокручивается тело таблицы внутри панели, а не вкладка целиком:
        // иначе режим и кнопки уезжали бы за верхний край вместе со списком.
        let state = state_with_rules(json!([]));
        let size = view(&state).as_widget().size();

        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn an_empty_ruleset_says_why_it_is_empty() {
        // Пустая панель читается как «не загрузилось», и человек ждёт.
        let state = State::default();
        assert!(state.config.routing.rules.is_empty());
        let _ = view(&state);
    }

    #[test]
    fn rules_render() {
        let state = state_with_rules(json!([
            { "id": "r1", "name": "Игры мимо", "when": { "process_name": ["steam.exe"] }, "action": "direct" },
            { "id": "r2", "name": "Локальная сеть", "when": { "dest_ip": ["10.0.0.0/8"] }, "action": "direct" }
        ]));
        assert_eq!(state.config.routing.rules.len(), 2);
        let _ = view(&state);
    }

    #[test]
    fn saving_appears_only_with_changes() {
        // Постоянно видимая «Сохранить» перестаёт что-либо значить.
        let mut state = state_with_rules(json!([]));
        assert!(!state.dirty);
        let _ = view(&state);

        state.dirty = true;
        let _ = view(&state);
    }

    #[test]
    fn a_long_ruleset_renders() {
        // Тридцать правил — то, ради чего на экране есть поиск и проверка.
        let rules: Vec<serde_json::Value> = (0..30)
            .map(|index| {
                json!({
                    "id": format!("r{index}"),
                    "name": format!("Правило {index}"),
                    "when": { "dest_port": [443] },
                    "action": "direct"
                })
            })
            .collect();
        let _ = view(&state_with_rules(json!(rules)));
    }

    #[test]
    fn columns_never_shift_between_the_head_and_a_row() {
        // Столбец, съехавший на знак, — единственное, что видно в таблице.
        let dim = Color::WHITE;
        let head: Element<'_, Message> = columns(
            glyphs(pad("ПРАВИЛО", NAME_WIDTH), dim),
            glyphs(pad("УСЛОВИЕ", CONDITION_WIDTH), dim),
            None,
            glyphs(lpad("ДЕЙСТВИЕ", ACTION_WIDTH), dim),
        );
        let row: Element<'_, Message> = columns(
            glyphs(pad("Игры мимо", NAME_WIDTH), dim),
            glyphs(pad("приложение: steam.exe", CONDITION_WIDTH), dim),
            None,
            glyphs(lpad("напрямую", ACTION_WIDTH), dim),
        );

        assert_eq!(head.as_widget().size(), row.as_widget().size());
    }

    #[test]
    fn every_action_keeps_the_width_of_its_column() {
        // Действие с именем профиля длиннее остальных, а на другом языке — ещё
        // длиннее; столбец, съехавший на таких строках, ломает таблицу целиком.
        for action in [
            RuleAction::Direct,
            RuleAction::Block,
            RuleAction::Tunnel { profile: None },
            RuleAction::Tunnel {
                profile: Some("office".to_owned()),
            },
        ] {
            let described = describe_action(&action);
            let placed = lpad(&table::clip(&described, ACTION_WIDTH), ACTION_WIDTH);
            assert_eq!(
                placed.chars().count(),
                ACTION_WIDTH,
                "`{described}` не встало в столбец действия"
            );
        }
    }

    #[test]
    fn a_rule_row_says_what_the_rule_does() {
        // Имя правило получает от человека и через месяц значит что угодно;
        // отвечает на вопрос «что это за правило» именно условие.
        let rule: RuleConfig = serde_json::from_value(json!({
            "id": "r1",
            "name": "Игры мимо",
            "when": { "process_name": ["steam.exe"] },
            "action": "direct"
        }))
        .expect("правило разбирается");

        assert_eq!(describe_condition(&rule.when), "приложение: steam.exe");
        assert_eq!(
            describe_action(&rule.action),
            crate::i18n::s().action_direct
        );
    }

    #[test]
    fn a_disabled_rule_stays_in_the_table() {
        // Спрятанное правило человек ищет и не находит.
        let state = state_with_rules(json!([
            { "id": "r1", "name": "Выключено", "enabled": false,
              "when": { "dest_port": [443] }, "action": "direct" }
        ]));
        assert!(!state.config.routing.rules[0].enabled);
        let _ = view(&state);
    }

    #[test]
    fn search_looks_at_the_name_the_condition_and_the_action() {
        // Правило вспоминают то по названию, то по приложению в нём.
        let rule: RuleConfig = serde_json::from_value(json!({
            "id": "r1",
            "name": "Игры мимо",
            "when": { "process_name": ["steam.exe"] },
            "action": "block"
        }))
        .expect("правило разбирается");

        assert!(found(&rule, ""));
        assert!(found(&rule, "игры"));
        assert!(found(&rule, "STEAM"));
        assert!(found(&rule, crate::i18n::s().action_block));
        assert!(!found(&rule, "нет такого"));
    }

    #[test]
    fn search_keeps_the_place_of_a_rule_in_the_set() {
        // Место правила — это его приоритет, и оно уезжает в сообщение об
        // удалении: после отбора второе правило стало бы первым.
        let mut state = state_with_rules(json!([
            { "id": "r1", "name": "Первое", "when": { "dest_port": [80] }, "action": "direct" },
            { "id": "r2", "name": "Второе", "when": { "dest_port": [443] }, "action": "block" }
        ]));
        state.split_tunnel.search = "Второе".to_owned();

        let places: Vec<usize> = state
            .config
            .routing
            .rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| found(rule, &state.split_tunnel.search))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(places, [1]);

        let _ = view(&state);
    }

    #[test]
    fn a_search_that_finds_nothing_says_so() {
        let mut state = state_with_rules(json!([
            { "id": "r1", "name": "Первое", "when": { "dest_port": [80] }, "action": "direct" }
        ]));
        state.split_tunnel.search = "нет такого".to_owned();
        let _ = view(&state);
    }

    #[test]
    fn describes_a_simple_leaf() {
        assert_eq!(
            describe_condition(&condition(json!({ "process_name": ["steam.exe"] }))),
            "приложение: steam.exe"
        );
    }

    #[test]
    fn shortens_long_lists() {
        // Двадцать отмеченных приложений в одной строке превращают таблицу
        // правил в стену текста.
        let apps: Vec<String> = (0..20).map(|index| format!("app{index}.exe")).collect();
        let described = describe_condition(&condition(json!({ "process_name": apps })));

        assert!(
            described.contains("ещё 17"),
            "список не обрезан: {described}"
        );
        assert!(described.len() < 80, "строка всё ещё длинная: {described}");
    }

    #[test]
    fn describes_nested_conditions() {
        let described = describe_condition(&condition(json!({
            "all": [
                { "process_name": ["steam.exe"] },
                { "domain_suffix": ["steamcontent.com"] }
            ]
        })));
        assert!(described.contains(" и "));
        assert!(described.contains("steam.exe"));
        assert!(described.contains("steamcontent.com"));
    }

    #[test]
    fn actions_are_told_apart() {
        // Одинаковые подписи у разных действий означают таблицу, по которой не
        // понять, что правило делает.
        let labels = [
            describe_action(&RuleAction::Direct),
            describe_action(&RuleAction::Block),
            describe_action(&RuleAction::Tunnel { profile: None }),
        ];
        let unique: std::collections::HashSet<&String> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len());
    }

    #[test]
    fn a_tunnel_with_a_profile_names_it() {
        let label = describe_action(&RuleAction::Tunnel {
            profile: Some("office".to_owned()),
        });
        assert!(label.contains("office"));
    }

    #[test]
    fn every_leaf_kind_is_described() {
        // Условие без описания выглядит в таблице пустой строкой, и правило
        // становится неотличимым от соседа.
        let leaves = [
            json!({ "process_path": ["c:/app.exe"] }),
            json!({ "process_name": ["app.exe"] }),
            json!({ "process_path_glob": ["c:/**/*.exe"] }),
            json!({ "domain": ["example.com"] }),
            json!({ "domain_suffix": ["example.com"] }),
            json!({ "domain_keyword": ["example"] }),
            json!({ "domain_regex": ["^ads"] }),
            json!({ "dest_ip": ["10.0.0.0/8"] }),
            json!({ "dest_port": [443] }),
            json!({ "dest_port_range": [[8000, 8100]] }),
            json!({ "geo_ip": ["RU"] }),
            json!({ "geo_site": ["ads"] }),
            json!({ "network": ["tcp"] }),
            json!({ "ip_version": ["v4"] }),
        ];

        for leaf in leaves {
            let described = describe_condition(&condition(leaf.clone()));
            assert!(!described.is_empty(), "нет описания для {leaf}");
            assert!(described.contains(':'), "описание без подписи: {described}");
        }
    }
}
