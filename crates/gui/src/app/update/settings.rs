//! Настройки приложения.
//!
//! Каждый переключатель уезжает демону сразу, без «Сохранить». Правила при этом
//! не уезжают: [`save`] берёт их из принятого демоном, иначе переключатель
//! сохранил бы набор, который правят на соседней вкладке.

use iced::Task;
use penguin_config::schema::app::LogLevel;

use crate::app::App;
use crate::app::message::{Message, SettingsMessage};
use crate::app::update::save;

/// Разбирает экран настроек.
pub fn handle(app: &mut App, message: SettingsMessage) -> Task<Message> {
    let config = &mut app.state_mut().config;
    match message {
        SettingsMessage::Autostart(enabled) => {
            config.app.autostart = enabled;
            apply_autostart(enabled);
        }
        SettingsMessage::Autoconnect(enabled) => config.app.autoconnect = enabled,
        SettingsMessage::KillSwitch(enabled) => config.network.kill_switch = enabled,
        SettingsMessage::AllowLan(enabled) => config.network.allow_lan = enabled,
        SettingsMessage::CaptureDefaultRoute(enabled) => {
            config.network.capture_default_route = enabled;
        }
        SettingsMessage::DnsHijack(enabled) => config.dns.hijack = enabled,
        SettingsMessage::VerboseLog(enabled) => config.app.log_level = log_level(enabled),
    }
    save(app)
}

/// Уровень журнала под переключателем: `debug` или `info`; `trace` ставят руками
/// в файле.
fn log_level(verbose: bool) -> LogLevel {
    if verbose {
        LogLevel::Debug
    } else {
        LogLevel::Info
    }
}

/// Автозапуск — запись в ветку текущего пользователя, её делает сам интерфейс
/// (у демона прав на неё нет). Неудача настройку не отменяет, только в журнал.
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
        let (app, _task) = App::new(uikit::ThemeType::Dark, false);
        app
    }

    #[test]
    fn toggles_reach_the_config_and_are_saved_at_once() {
        let mut app = app();

        let _ = handle(&mut app, SettingsMessage::KillSwitch(false));
        assert!(!app.state().config.network.kill_switch);
        assert!(!app.state().saved.network.kill_switch, "не уехало демону");

        let _ = handle(&mut app, SettingsMessage::AllowLan(false));
        assert!(!app.state().saved.network.allow_lan);

        let _ = handle(&mut app, SettingsMessage::Autoconnect(true));
        assert!(app.state().saved.app.autoconnect);

        let _ = handle(&mut app, SettingsMessage::CaptureDefaultRoute(false));
        assert!(!app.state().saved.network.capture_default_route);

        let _ = handle(&mut app, SettingsMessage::DnsHijack(false));
        assert!(!app.state().saved.dns.hijack);

        let _ = handle(&mut app, SettingsMessage::VerboseLog(true));
        assert_eq!(app.state().saved.app.log_level, LogLevel::Debug);

        assert!(
            !app.state().dirty,
            "сохранять больше нечего — и предлагать нечего"
        );
    }

    #[test]
    fn a_toggle_does_not_save_rules_the_user_is_still_editing() {
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
