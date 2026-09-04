//! Настройки приложения.
//!
//! Каждый переключатель уезжает демону сразу, без «Сохранить». Настройка здесь
//! — это один флаг, а не набор, который собирают и подтверждают целиком:
//! щелчок, после которого ничего не произошло, пока не нажата вторая кнопка,
//! читается как несработавший, и человек щёлкает ещё раз.
//!
//! Правила при этом не уезжают: их берёт [`save`] из того, что уже принял
//! демон. Иначе переключатель на этой вкладке молча сохранял бы набор правил,
//! который человек ещё правит на соседней.

use iced::Task;

use crate::app::App;
use crate::app::message::{Message, SettingsMessage};
use crate::app::update::save;

/// Разбирает экран настроек.
pub fn handle(app: &mut App, message: SettingsMessage) -> Task<Message> {
    match message {
        SettingsMessage::Autostart(enabled) => {
            app.state_mut().config.app.autostart = enabled;

            // Автозапуск интерфейса — запись в ветку текущего пользователя, и
            // делает её сам интерфейс: демону она не нужна и прав на неё у
            // него нет.
            apply_autostart(enabled);
            save(app)
        }

        SettingsMessage::Autoconnect(enabled) => {
            app.state_mut().config.app.autoconnect = enabled;
            save(app)
        }

        SettingsMessage::KillSwitch(enabled) => {
            app.state_mut().config.network.kill_switch = enabled;
            save(app)
        }

        SettingsMessage::AllowLan(enabled) => {
            app.state_mut().config.network.allow_lan = enabled;
            save(app)
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
        let (app, _task) = App::new(uikit::ThemeType::Dark);
        app
    }

    #[test]
    fn toggles_reach_the_config_and_are_saved_at_once() {
        // Щелчок, после которого ничего не произошло, читается как
        // несработавший, и человек щёлкает ещё раз.
        let mut app = app();

        let _ = handle(&mut app, SettingsMessage::KillSwitch(false));
        assert!(!app.state().config.network.kill_switch);
        assert!(!app.state().saved.network.kill_switch, "не уехало демону");

        let _ = handle(&mut app, SettingsMessage::AllowLan(false));
        assert!(!app.state().saved.network.allow_lan);

        let _ = handle(&mut app, SettingsMessage::Autoconnect(true));
        assert!(app.state().saved.app.autoconnect);

        assert!(
            !app.state().dirty,
            "сохранять больше нечего — и предлагать нечего"
        );
    }

    #[test]
    fn a_toggle_does_not_save_rules_the_user_is_still_editing() {
        // Иначе щелчок по переключателю на этой вкладке молча сохраняет набор
        // правил, который человек правит на соседней.
        let mut app = app();
        app.state_mut().config.routing.mode =
            penguin_config::schema::routing::TunnelMode::Allowlist;
        app.state_mut().dirty = true;

        let _ = handle(&mut app, SettingsMessage::AllowLan(false));

        assert_eq!(
            app.state().saved.routing.mode,
            penguin_config::schema::routing::TunnelMode::default(),
            "неподтверждённое правило уехало демону"
        );
        assert!(app.state().dirty, "правило всё ещё ждёт «Сохранить»");
    }
}
