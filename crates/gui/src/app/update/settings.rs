//! Настройки приложения.

use iced::Command;
use penguin_ipc::schema::Request;

use crate::app::App;
use crate::app::message::{Message, SettingsMessage};
use crate::app::update::request;

/// Разбирает экран настроек.
pub fn handle(app: &mut App, message: SettingsMessage) -> Command<Message> {
    match message {
        SettingsMessage::AutostartToggled(enabled) => {
            app.state_mut().config.app.autostart = enabled;
            app.state_mut().dirty = true;

            // Автозапуск интерфейса — запись в ветку текущего пользователя, и
            // делает её сам интерфейс: демону она не нужна и прав на неё у
            // него нет.
            apply_autostart(enabled);
            Command::none()
        }

        SettingsMessage::AutoconnectToggled(enabled) => {
            app.state_mut().config.app.autoconnect = enabled;
            app.state_mut().dirty = true;
            Command::none()
        }

        SettingsMessage::KillSwitchToggled(enabled) => {
            app.state_mut().config.network.kill_switch = enabled;
            app.state_mut().dirty = true;
            Command::none()
        }

        SettingsMessage::AllowLanToggled(enabled) => {
            app.state_mut().config.network.allow_lan = enabled;
            app.state_mut().dirty = true;
            Command::none()
        }

        SettingsMessage::Save => {
            let config = app.state().config.clone();
            app.state_mut().dirty = false;
            request(Request::SetConfig {
                config: Box::new(config),
            })
        }
    }
}

/// Включает или выключает автозапуск интерфейса.
///
/// Неудача не отменяет саму настройку: она сохранится и подействует, когда
/// права появятся. Молча промолчать нельзя — строка попадёт в журнал.
fn apply_autostart(enabled: bool) {
    let result = if enabled {
        std::env::current_exe()
            .map_err(|e| penguin_platform::PlatformError::Service(e.to_string()))
            .and_then(|path| penguin_platform::autostart::enable(&path))
    } else {
        penguin_platform::autostart::disable()
    };

    if let Err(err) = result {
        tracing::warn!(%err, "автозапуск не изменён");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        let (app, _command) = <App as iced::Application>::new(uikit::ThemeType::Dark);
        app
    }

    #[test]
    fn toggles_reach_the_config() {
        let mut app = app();

        let _ = handle(&mut app, SettingsMessage::KillSwitchToggled(false));
        assert!(!app.state().config.network.kill_switch);

        let _ = handle(&mut app, SettingsMessage::AllowLanToggled(false));
        assert!(!app.state().config.network.allow_lan);

        let _ = handle(&mut app, SettingsMessage::AutoconnectToggled(true));
        assert!(app.state().config.app.autoconnect);

        assert!(
            app.state().dirty,
            "правки должны быть видны как несохранённые"
        );
    }

    #[test]
    fn saving_clears_the_dirty_flag() {
        let mut app = app();
        let _ = handle(&mut app, SettingsMessage::AutoconnectToggled(true));
        assert!(app.state().dirty);

        let _ = handle(&mut app, SettingsMessage::Save);
        assert!(!app.state().dirty);
    }
}
