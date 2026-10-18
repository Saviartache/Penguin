//! Серверы и профили: список, правка в модальном окне, новый сервер в два шага
//! (протокол — [`picker`], его форма — [`editor`]).
//!
//! Заголовка и прокрутки вокруг списка нет: прокручивается список в панели, отступ
//! даёт окно ([`crate::app::PAGE_PADDING`]).

pub mod editor;
pub mod list;
pub mod picker;
pub mod wireguard;

use iced::Element;
use penguin_config::schema::profile::Profile;

use crate::app::message::Message;
use crate::app::state::State;

/// Собирает экран; модальное окно заменяет тело (наложений в `iced` нет).
pub fn view(state: &State) -> Element<'_, Message> {
    // Порядок — порядок шагов: выбор протокола, способ WireGuard, потом форма.
    if state.servers.picker {
        return picker::view(state);
    }
    if state.servers.wireguard {
        return wireguard::view(state);
    }
    if let Some(draft) = state.servers.editor.as_ref() {
        return editor::view(state, draft);
    }

    list::view(state)
}

/// Адрес сервера из непрозрачных параметров; `None` — адреса нет, чем заполнить
/// пустоту, решает рисующий (имя протокола дублировало бы соседний столбец).
pub fn server_of(profile: &Profile) -> Option<&str> {
    profile
        .outbound
        .field("server")
        .and_then(|value| value.as_str())
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
        assert_eq!(server_of(&profile), Some("example.com:443"));
    }

    #[test]
    fn a_profile_without_an_address_says_nothing_instead_of_the_protocol() {
        let profile = Profile::new("x", "x", RawOutbound::new("vless", json!({})));
        assert_eq!(server_of(&profile), None);
    }

    #[test]
    fn renders_the_list_when_the_editor_is_closed() {
        let state = State::default();
        assert!(state.servers.editor.is_none());
        let _ = view(&state);
    }

    #[test]
    fn the_editor_replaces_the_list() {
        let mut state = State::default();
        state.servers.editor = Some(crate::forms::server::Draft::default());
        let _ = view(&state);
    }

    #[test]
    fn the_protocol_list_comes_before_the_form() {
        let mut state = State::default();
        state.servers.picker = true;
        state.servers.editor = Some(crate::forms::server::Draft::default());
        let _ = view(&state);
    }
}
