//! Как добавить WireGuard: вручную, из файла `.conf` или подпиской Amnezia.
//!
//! Второй шаг после выбора «WireGuard» в [`super::picker`]. Ручной ввод ведёт в
//! обычную форму; `.conf` — единичный экспорт из Amnezia; подписка — ключ
//! `vpn://…`, по которому серверы тянутся со шлюза.

use iced::{Alignment, Element};
use uikit::layout::{Flex, Sizable, Size, gap, px};
use uikit::tokens::type_scale;
use uikit::widgets::{ButtonVariant, Modal};

use crate::app::message::{Message, ServersMessage};
use crate::app::state::State;
use crate::screens::table::{self, BUTTON_HEIGHT};
use crate::ui;

/// Ширина окна — как у формы и выбора протокола.
const WIDTH: f32 = 620.0;

/// Собирает окно выбора способа.
pub fn view(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    let busy = state.servers.subscription_busy;

    let manual = ui::button(ButtonVariant::Secondary, strings.wireguard_manual)
        .h(px(BUTTON_HEIGHT))
        .on_press(Message::Servers(ServersMessage::WireguardManual));

    let mut from_conf =
        ui::button(ButtonVariant::Secondary, strings.wireguard_from_conf).h(px(BUTTON_HEIGHT));
    if !busy {
        from_conf = from_conf.on_press(Message::Servers(ServersMessage::WireguardFromConf));
    }

    let methods = Flex::row()
        .push(manual)
        .push(from_conf)
        .gap(gap::SM)
        .build();

    let body = Flex::col()
        .w(Size::FILL)
        .push_auto(methods)
        .push_auto(subscription(state))
        .gap(gap::MD)
        .build();

    Modal::new(body)
        .title(strings.wireguard_add)
        .max_width(WIDTH)
        .on_close(Message::Servers(ServersMessage::WireguardClosed))
        .on_backdrop(Message::Servers(ServersMessage::WireguardClosed))
        .build()
        .into()
}

/// Строка подписки: ключ `vpn://…` и кнопка обновления.
fn subscription(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    let input = table::search(
        strings.subscription_key_hint,
        &state.servers.subscription_key,
        |value| Message::Servers(ServersMessage::SubscriptionKeyChanged(value)),
    );

    let mut refresh =
        ui::button(ButtonVariant::Primary, strings.subscription_refresh).h(px(BUTTON_HEIGHT));
    if !state.servers.subscription_busy && !state.servers.subscription_key.trim().is_empty() {
        refresh = refresh.on_press(Message::Servers(ServersMessage::SubscriptionRefresh));
    }

    let row = Flex::row()
        .push(input)
        .push_auto(refresh)
        .gap(gap::SM)
        .align(Alignment::Center)
        .build();

    Flex::col()
        .w(Size::FILL)
        .push_auto(ui::muted(
            &state.palette,
            strings.subscription,
            type_scale::LEAD,
        ))
        .push_auto(row)
        .gap(gap::XS)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_method_chooser() {
        let mut state = State::default();
        state.servers.wireguard = true;
        let _ = view(&state);
    }
}
