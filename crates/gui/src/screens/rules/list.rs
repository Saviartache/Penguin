//! Список правил.
//!
//! Каждая строка показывает то, чего в файле настроек не видно сразу: **что
//! правило делает** и **при каком условии**. Условие описывается словами — тем
//! же кодом для всех строк, чтобы список и объяснение не разошлись.
//!
//! Действие — меткой с тоном, а не словом в общем ряду: в списке из тридцати
//! правил взгляд ищет цветом, а не читает подписи подряд.

use iced::widget::text;
use iced::{Alignment, Element};
use penguin_config::schema::rule::{Condition, Leaf, RuleAction, RuleConfig};
use uikit::layout::{Flex, gap};
use uikit::style::tokens::type_scale;
use uikit::widgets::badge::Tone;
use uikit::widgets::{Badge, ButtonVariant, Checkbox};

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::ui;

/// Собирает раздел со списком правил.
pub fn view(state: &State) -> Element<'_, Message> {
    let palette = &state.palette;
    let rules = &state.config.routing.rules;

    let content: Element<'_, Message> = if rules.is_empty() {
        ui::empty(palette, crate::i18n::s().no_rules)
    } else {
        let rows = rules
            .iter()
            .enumerate()
            .map(|(index, rule)| row(state, index, rule))
            .collect::<Vec<_>>();

        Flex::col().extend(rows).gap(gap::MD).build()
    };

    ui::section(palette, crate::i18n::s().rules, None, content)
}

/// Одна строка правила.
fn row<'a>(state: &'a State, index: usize, rule: &'a RuleConfig) -> Element<'a, Message> {
    let palette = &state.palette;
    let (action_label, tone) = describe_action(&rule.action);

    let name = if rule.name.is_empty() {
        rule.id.clone()
    } else {
        rule.name.clone()
    };

    let title = Flex::col()
        .push_auto(text(name).size(type_scale::LEAD))
        .push_auto(ui::faint(
            palette,
            describe_condition(&rule.when),
            type_scale::MICRO,
        ))
        .gap(gap::XS)
        .build();

    Flex::row()
        .push_auto(
            Checkbox::new(String::new(), rule.enabled).on_toggle(move |value| {
                Message::SplitTunnel(SplitTunnelMessage::RuleToggled(index, value))
            }),
        )
        .push(title)
        .push_auto(Badge::new(action_label).tone(tone).build())
        .push_auto(
            ui::button(ButtonVariant::Neutral, crate::i18n::s().remove)
                .on_press(Message::SplitTunnel(SplitTunnelMessage::RuleRemoved(index))),
        )
        .gap(gap::MD)
        .align(Alignment::Center)
        .build()
}

/// Подпись и тон действия.
pub fn describe_action(action: &RuleAction) -> (String, Tone) {
    match action {
        RuleAction::Tunnel {
            profile: Some(profile),
        } => (
            format!("{} → {profile}", crate::i18n::s().action_tunnel),
            Tone::Accent,
        ),
        RuleAction::Tunnel { profile: None } => {
            (crate::i18n::s().action_tunnel.to_owned(), Tone::Accent)
        }
        RuleAction::Direct => (crate::i18n::s().action_direct.to_owned(), Tone::Neutral),
        RuleAction::Block => (crate::i18n::s().action_block.to_owned(), Tone::Danger),
    }
}

/// Описывает условие словами.
///
/// Короче, чем описание в проверке правил: в списке важно узнать правило, а не
/// разобрать его целиком. Полное описание показывает раздел проверки.
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
    /// Двадцать отмеченных приложений в одной строке превращают список правил
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
    use serde_json::json;

    use super::*;

    fn condition(value: serde_json::Value) -> Condition {
        serde_json::from_value(value).expect("условие разбирается")
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
        // Двадцать отмеченных приложений в одной строке превращают список
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
    fn actions_are_toned_apart() {
        // В списке из тридцати правил взгляд ищет цветом.
        assert_eq!(describe_action(&RuleAction::Direct).1, Tone::Neutral);
        assert_eq!(describe_action(&RuleAction::Block).1, Tone::Danger);
        assert_eq!(
            describe_action(&RuleAction::Tunnel { profile: None }).1,
            Tone::Accent
        );
    }

    #[test]
    fn a_tunnel_with_a_profile_names_it() {
        let (label, _) = describe_action(&RuleAction::Tunnel {
            profile: Some("office".to_owned()),
        });
        assert!(label.contains("office"));
    }

    #[test]
    fn every_leaf_kind_is_described() {
        // Условие без описания выглядит в списке пустой строкой, и правило
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

    #[test]
    fn renders_an_empty_and_a_filled_list() {
        let mut state = State::default();
        let _ = view(&state);

        state.config.routing.rules = serde_json::from_value(json!([
            { "id": "r1", "name": "Игры", "when": { "process_name": ["steam.exe"] }, "action": "direct" }
        ]))
        .expect("правила разбираются");
        let _ = view(&state);
    }
}
