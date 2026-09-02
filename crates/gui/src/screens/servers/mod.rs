//! Серверы и профили.
//!
//! Экран сведён к двум вещам: что можно сделать и что уже есть. Заголовка нет
//! намеренно — он повторял бы подпись вкладки, по которой сюда и пришли, и
//! съедал бы строку в самом видном месте ради второго «Серверы» подряд.
//!
//! Правка профиля идёт в модальном окне, а не рядом со списком. Форма из
//! девяти полей под списком отодвигает сам список за нижний край, и человек
//! правит один сервер, не видя остальных, — тогда как выбирают их именно
//! сравнением.

pub mod editor;
pub mod list;

use iced::Element;
use penguin_config::schema::profile::Profile;

use crate::app::message::Message;
use crate::app::state::State;
use crate::ui;

/// Собирает экран.
pub fn view(state: &State) -> Element<'_, Message> {
    // Модальное окно **заменяет** тело экрана: в `iced 0.12` наложения поверх
    // содержимого нет, и так это устроено в самом ките.
    if let Some(draft) = state.servers.editor.as_ref() {
        return editor::view(state, draft);
    }

    ui::page_bare(vec![list::view(state)])
}

/// Адрес сервера для подписи.
///
/// Из непрозрачных параметров, а не разбором конфигурации протокола: окно не
/// знает, какой протокол за профилем, и знать не должно.
pub fn server_of(profile: &Profile) -> String {
    profile
        .outbound
        .field("server")
        .and_then(|value| value.as_str())
        .unwrap_or(&profile.outbound.protocol)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::outbound::RawOutbound;
    use serde_json::json;

    use super::*;

    #[test]
    fn the_address_comes_from_opaque_params() {
        let profile = Profile::new(
            "home",
            "Дом",
            RawOutbound::new("hysteria2", json!({ "server": "example.com:443" })),
        );
        assert_eq!(server_of(&profile), "example.com:443");
    }

    #[test]
    fn a_profile_without_an_address_still_says_something() {
        let profile = Profile::new("x", "x", RawOutbound::new("vless", json!({})));
        assert_eq!(server_of(&profile), "vless");
    }

    #[test]
    fn renders_the_list_when_the_editor_is_closed() {
        let state = State::default();
        assert!(state.servers.editor.is_none());
        let _ = view(&state);
    }

    #[test]
    fn the_editor_replaces_the_list() {
        // В `iced 0.12` наложения поверх содержимого нет: модальное окно
        // занимает место тела экрана целиком.
        let mut state = State::default();
        state.servers.editor = Some(crate::forms::server::Draft::default());
        let _ = view(&state);
    }
}
