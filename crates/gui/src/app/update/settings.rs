//! Настройки приложения.
//!
//! Каждый переключатель уезжает демону сразу, без «Сохранить». Правила при этом
//! не уезжают: [`save`] берёт их из принятого демоном, иначе переключатель
//! сохранил бы набор, который правят на соседней вкладке.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use iced::Task;
use penguin_config::schema::app::{Language, LogLevel};
use penguin_config::schema::dns::DnsMode;
use penguin_config::schema::network::InboundConfig;

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
        SettingsMessage::CheckUpdates(enabled) => config.app.check_updates = enabled,
        SettingsMessage::NextLanguage => {
            config.app.language = next_language(config.app.language);
            crate::i18n::set_language(config.app.language);
            // Меню лотка собрано на прежнем языке.
            app.rebuild_tray();
        }
        SettingsMessage::Ipv6(enabled) => config.network.tun.ipv6_enabled = enabled,
        SettingsMessage::NextDnsMode => config.dns.mode = next_dns_mode(config.dns.mode),
        SettingsMessage::Socks(enabled) => config.network.socks = inbound(enabled, SOCKS_LISTEN),
        SettingsMessage::Http(enabled) => config.network.http = inbound(enabled, HTTP_LISTEN),
        #[cfg(target_os = "macos")]
        SettingsMessage::DockIcon(enabled) => {
            config.app.dock_icon = enabled;
            app.sync_dock();
        }
    }
    save(app)
}

/// Адрес SOCKS5, если включают из окна.
pub(crate) const SOCKS_LISTEN: SocketAddr = local(1080);

/// Адрес HTTP-прокси, если включают из окна.
pub(crate) const HTTP_LISTEN: SocketAddr = local(8080);

const fn local(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// Прокси на loopback без пароля; выключение забывает и адрес, заданный в файле.
fn inbound(enabled: bool, listen: SocketAddr) -> Option<InboundConfig> {
    enabled.then_some(InboundConfig { listen, auth: None })
}

fn next_language(language: Language) -> Language {
    match language {
        Language::Ru => Language::En,
        Language::En => Language::Ru,
    }
}

fn next_dns_mode(mode: DnsMode) -> DnsMode {
    match mode {
        DnsMode::FakeIp => DnsMode::Resolve,
        DnsMode::Resolve => DnsMode::System,
        DnsMode::System => DnsMode::FakeIp,
    }
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

        let _ = handle(&mut app, SettingsMessage::Ipv6(true));
        assert!(app.state().saved.network.tun.ipv6_enabled);

        let _ = handle(&mut app, SettingsMessage::NextDnsMode);
        assert_eq!(app.state().saved.dns.mode, DnsMode::Resolve);

        assert!(
            !app.state().dirty,
            "сохранять больше нечего — и предлагать нечего"
        );
    }

    #[test]
    fn local_proxies_listen_on_loopback_and_pass_validation() {
        let mut app = app();

        let _ = handle(&mut app, SettingsMessage::Socks(true));
        let _ = handle(&mut app, SettingsMessage::Http(true));
        let saved = &app.state().saved;
        assert_eq!(
            saved.network.socks.as_ref().map(|i| i.listen),
            Some(SOCKS_LISTEN)
        );
        assert_eq!(
            saved.network.http.as_ref().map(|i| i.listen),
            Some(HTTP_LISTEN)
        );
        assert!(SOCKS_LISTEN.ip().is_loopback() && HTTP_LISTEN.ip().is_loopback());
        penguin_config::validate::validate(saved)
            .expect("включённые из окна прокси проходят проверку");

        let _ = handle(&mut app, SettingsMessage::Socks(false));
        assert!(app.state().saved.network.socks.is_none());
    }

    #[test]
    fn choices_cycle_through_every_value() {
        let mut mode = DnsMode::FakeIp;
        for _ in 0..3 {
            mode = next_dns_mode(mode);
        }
        assert_eq!(mode, DnsMode::FakeIp);
        assert_eq!(next_language(next_language(Language::Ru)), Language::Ru);
    }

    #[test]
    fn a_toggle_does_not_save_rules_the_user_is_still_editing() {
        let mut app = app();
        app.state_mut().config.routing.mode = penguin_config::schema::routing::TunnelMode::Direct;
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
