//! Модальное окно обновления: что найдено и кнопка установить.
//!
//! Узкое, чтобы помещаться и в компактное окно: показывается поверх любого вида.

use iced::Element;
use iced::widget::text;
use uikit::tokens::type_scale;
use uikit::widgets::Modal;

use crate::app::message::{Message, UpdateMessage};
use crate::app::state::{State, UpdateStatus};
use crate::screens::settings::status_line;

/// Ширина окна — по компактному виду.
const WIDTH: f32 = 320.0;

/// Собирает модальное окно обновления.
pub fn view(state: &State) -> Element<'_, Message> {
    let status = &state.updates.status;
    let content = text(status_line(status)).size(type_scale::BODY);

    let mut modal = Modal::new(content)
        .title(crate::i18n::s().update_title)
        .max_width(WIDTH)
        .on_close(Message::Update(UpdateMessage::Dismissed))
        .on_backdrop(Message::Update(UpdateMessage::Dismissed));

    if matches!(status, UpdateStatus::Available(_)) {
        modal = modal.action(
            crate::i18n::s().update_install,
            Message::Update(UpdateMessage::Install),
        );
    }

    modal.build().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_update_state_renders() {
        let mut state = State::default();
        for status in [
            UpdateStatus::Available(penguin_update::Available {
                version: "9.9.9".into(),
                page_url: String::new(),
                archive_name: String::new(),
                archive_url: String::new(),
                sums_url: String::new(),
            }),
            UpdateStatus::Installing,
            UpdateStatus::Failed("нет сети".into()),
        ] {
            state.updates.status = status;
            let _ = view(&state);
        }
    }
}
