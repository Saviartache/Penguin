//! Серверы и профили.
//!
//! Экран сведён к двум вещам: что можно сделать и что уже есть. Заголовка нет
//! намеренно — он повторял бы подпись вкладки, по которой сюда и пришли, и
//! съедал бы строку в самом видном месте ради второго «Серверы» подряд.
//!
//! Страницы с прокруткой вокруг списка тоже нет. Она добавляла второй отступ
//! поверх отступа окна, и кнопки экрана стояли левее вкладок на целый отступ;
//! а прокручиваться здесь должен список внутри панели, а не панель вместе с
//! кнопками. Поэтому экран отдаёт содержимое как есть, растянутым по обеим
//! осям, — отступ от края даёт окно ([`crate::app::PAGE_PADDING`]), один и тот
//! же слева, справа и снизу.
//!
//! Правка профиля идёт в модальном окне, а не рядом со списком. Форма из
//! девяти полей под списком отодвигает сам список за нижний край, и человек
//! правит один сервер, не видя остальных, — тогда как выбирают их именно
//! сравнением.
//!
//! Новый сервер заводится в два шага: сначала протокол ([`picker`]), потом его
//! форма ([`editor`]). Поля формы **и есть** протокол, и показывать их до того,
//! как он выбран, нечем.

pub mod editor;
pub mod list;
pub mod picker;

use iced::Element;
use penguin_config::schema::profile::Profile;

use crate::app::message::Message;
use crate::app::state::State;

/// Собирает экран.
pub fn view(state: &State) -> Element<'_, Message> {
    // Модальное окно **заменяет** тело экрана: в `iced 0.12` наложения поверх
    // содержимого нет, и так это устроено в самом ките.
    //
    // Порядок веток — порядок шагов: выбор протокола, потом его форма. Открыт
    // может быть только один из них: выбор протокола закрывает себя, открывая
    // форму.
    if state.servers.picker {
        return picker::view(state);
    }
    if let Some(draft) = state.servers.editor.as_ref() {
        return editor::view(state, draft);
    }

    list::view(state)
}

/// Адрес сервера для подписи.
///
/// Из непрозрачных параметров, а не разбором конфигурации протокола: окно не
/// знает, какой протокол за профилем, и знать не должно.
///
/// `None` — адреса в параметрах нет. Раньше на его месте подставлялось имя
/// протокола, и это было честно, пока протокол больше нигде не показывали.
/// Теперь у него свой столбец, и такая подстановка означала бы одно и то же
/// значение в двух соседних клетках — ровно та путаница, ради которой столбцы
/// и разделяют. Чем заполнить пустоту, решает тот, кто рисует: у него есть
/// прочерк, который заведомо есть в шрифте.
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
        // Имя протокола на месте адреса повторяло бы соседний столбец.
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
        // В `iced 0.12` наложения поверх содержимого нет: модальное окно
        // занимает место тела экрана целиком.
        let mut state = State::default();
        state.servers.editor = Some(crate::forms::server::Draft::default());
        let _ = view(&state);
    }

    #[test]
    fn the_protocol_list_comes_before_the_form() {
        // Оба открытыми быть не должны, но если такое случилось — показать
        // надо первый шаг, а не второй.
        let mut state = State::default();
        state.servers.picker = true;
        state.servers.editor = Some(crate::forms::server::Draft::default());
        let _ = view(&state);
    }
}
