//! Раздел адресов или портов в окне группы: поле и список значений.
//!
//! Поле делает два дела: пока его набирают, оно ищет по списку (в группе бывают
//! сотни доменов), а Enter добавляет набранное. Понятое раскладывается по
//! разделам само — порт, вписанный среди адресов, уходит в порты; непонятое
//! остаётся в поле, чтобы его поправили.

use iced::theme::Palette;
use iced::widget::text;
use iced::{Alignment, Element};
use uikit::layout::{Flex, gap};
use uikit::tokens::type_scale;
use uikit::widgets::{ButtonVariant, TextInput};

use crate::app::message::{Message, SplitTunnelMessage};
use crate::app::state::State;
use crate::forms::punycode::to_unicode;
use crate::forms::rule::{Draft, HostKind, Section, host_kind};
use crate::screens::table;
use crate::ui;

/// Ширина кнопки «убрать» — как у кнопок строки таблицы групп.
const REMOVE_WIDTH: f32 = 30.0;

/// Собирает раздел; `height` — высота списка, общая с разделом приложений.
pub fn view<'a>(
    state: &'a State,
    draft: &'a Draft,
    section: Section,
    height: f32,
) -> Element<'a, Message> {
    let strings = crate::i18n::s();
    let entry = &state.split_tunnel.entry;

    let hint = match section {
        Section::Ports => strings.ports_hint,
        Section::Apps | Section::Hosts => strings.hosts_hint,
    };
    let mut add = ui::button(ButtonVariant::Secondary, strings.add);
    if !entry.trim().is_empty() {
        add = add.on_press(Message::SplitTunnel(
            SplitTunnelMessage::DraftEntrySubmitted,
        ));
    }
    let field = Flex::row()
        .push(
            TextInput::new(hint, entry)
                .on_input(|value| {
                    Message::SplitTunnel(SplitTunnelMessage::DraftEntryChanged(value))
                })
                .on_submit(Message::SplitTunnel(
                    SplitTunnelMessage::DraftEntrySubmitted,
                ))
                .build(),
        )
        .push_auto(add)
        .gap(gap::SM)
        .align(Alignment::Center)
        .build();

    let values = draft.values(section);
    let shown = matching(values, entry);
    let list: Element<'a, Message> = if values.is_empty() {
        ui::empty(&state.palette, strings.values_empty)
    } else if shown.is_empty() {
        ui::empty(&state.palette, strings.values_not_found)
    } else {
        let rows = shown
            .into_iter()
            .map(|value| row(&state.palette, value))
            .collect::<Vec<_>>();
        ui::scroll_box(Flex::col().extend(rows).gap(gap::XS).build(), height)
    };

    Flex::col()
        .push_auto(field)
        .push_auto(list)
        .gap(gap::SM)
        .build()
}

/// Строка значения с кнопкой «убрать».
fn row<'a>(palette: &Palette, value: &'a str) -> Element<'a, Message> {
    // Пометка вида (`=`, `*…*`, `.`) — для ввода; в списке вид сказан словами,
    // а имя `xn--…` — кириллицей, как его вписали.
    let strings = crate::i18n::s();
    let (shown, kind) = match host_kind(value) {
        Some((HostKind::Exact, name)) => (to_unicode(name), Some(strings.host_exact)),
        Some((HostKind::Keyword, word)) => (word.to_owned(), Some(strings.host_keyword)),
        Some((HostKind::Zone, zone)) => (format!(".{}", to_unicode(zone)), Some(strings.host_zone)),
        Some((HostKind::Country, code)) => (code.to_owned(), Some(strings.host_country)),
        Some((HostKind::Suffix, name)) => (to_unicode(name), None),
        _ => (value.to_owned(), None),
    };

    let mut line = Flex::row().push_auto(text(shown).size(type_scale::BODY));
    if let Some(kind) = kind {
        line = line.push_auto(ui::faint(palette, kind, type_scale::MICRO));
    }
    line.push(ui::spring())
        .push_auto(table::action(
            "×",
            REMOVE_WIDTH,
            Message::SplitTunnel(SplitTunnelMessage::DraftValueRemoved(value.to_owned())),
        ))
        .gap(gap::SM)
        .align(Alignment::Center)
        .build()
}

/// Значения, в которых встречается набранное; пустое поле — все.
pub fn matching<'a>(values: &'a [String], entry: &str) -> Vec<&'a String> {
    let query = entry.trim().to_lowercase();
    values
        .iter()
        .filter(|value| query.is_empty() || value.to_lowercase().contains(&query))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_field_searches_the_list() {
        let values = vec![
            "google.com".to_owned(),
            "youtube.com".to_owned(),
            "10.0.0.0/8".to_owned(),
        ];
        assert_eq!(matching(&values, "").len(), 3);
        assert_eq!(matching(&values, " GOO "), [&values[0]]);
        assert!(matching(&values, "bing").is_empty());
    }

    #[test]
    fn renders_empty_full_and_filtered() {
        let mut state = State::default();
        let mut draft = Draft::default();
        let _ = view(&state, &draft, Section::Hosts, 140.0);

        draft.add("google.com 10.0.0.0/8 443");
        let _ = view(&state, &draft, Section::Hosts, 140.0);
        let _ = view(&state, &draft, Section::Ports, 140.0);

        state.split_tunnel.entry = "nothing".to_owned();
        let _ = view(&state, &draft, Section::Hosts, 140.0);
    }
}
