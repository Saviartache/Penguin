//! Настройки — панель терминала во всю вкладку: разделы и переключатели без
//! шапки и поиска ([`crate::screens::table::sheet`]).
//!
//! Значение и есть флажок: `[ ВКЛ  ]` / `[ ВЫКЛ ]`, переключает щелчок по строке.
//! Кнопки «Сохранить» нет: каждый флаг уезжает демону сразу, правила остаются
//! неподтверждёнными ([`crate::app::update::save`]). Темы нет: её переключает
//! кружок в шапке.
//!
//! «Запуск» трогает только это окно, «Сеть» и «DNS» — весь трафик системы,
//! «Локальный прокси» — только приложения, настроенные на него, «Журнал» ничего.
//! Строки одной системы (значок в Dock) собираются только под неё.

use std::net::SocketAddr;

use iced::widget::button;
use iced::widget::text::IntoFragment;
use iced::{Alignment, Element, Length};
use penguin_config::schema::app::Language;
use penguin_config::schema::dns::DnsMode;
use penguin_config::schema::network::InboundConfig;
use uikit::layout::{Flex, Sizable, Size, gap};
use uikit::tokens::ink;

use crate::app::message::{Message, SettingsMessage, UpdateMessage};
use crate::app::state::{State, UpdateStatus};
use crate::app::update::settings::{HTTP_LISTEN, SOCKS_LISTEN};
use crate::screens::table::{self, CELL, ROW_GAP, ROW_PADDING, glyphs, pad};
use crate::ui;

/// Собирает экран.
pub fn view(state: &State) -> Element<'_, Message> {
    panel(state)
}

fn panel(state: &State) -> Element<'_, Message> {
    let strings = crate::i18n::s();
    let config = &state.config;

    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut startup_rows = vec![
        switch(
            state,
            strings.autostart,
            config.app.autostart,
            SettingsMessage::Autostart,
        ),
        switch(
            state,
            strings.autoconnect,
            config.app.autoconnect,
            SettingsMessage::Autoconnect,
        ),
        choice(
            state,
            strings.language,
            crate::i18n::language_name(config.app.language),
            &[Language::Ru, Language::En].map(crate::i18n::language_name),
            SettingsMessage::NextLanguage,
        ),
    ];
    #[cfg(target_os = "macos")]
    startup_rows.push(switch(
        state,
        strings.dock_icon,
        config.app.dock_icon,
        SettingsMessage::DockIcon,
    ));
    let startup = section(state, strings.startup, startup_rows);

    let network = section(
        state,
        strings.network,
        vec![
            switch(
                state,
                strings.kill_switch,
                config.network.kill_switch,
                SettingsMessage::KillSwitch,
            ),
            switch(
                state,
                strings.allow_lan,
                config.network.allow_lan,
                SettingsMessage::AllowLan,
            ),
            switch(
                state,
                strings.capture_default_route,
                config.network.capture_default_route,
                SettingsMessage::CaptureDefaultRoute,
            ),
            switch(
                state,
                strings.ipv6,
                config.network.tun.ipv6_enabled,
                SettingsMessage::Ipv6,
            ),
        ],
    );

    let dns = section(
        state,
        strings.dns,
        vec![
            switch(
                state,
                strings.dns_hijack,
                config.dns.hijack,
                SettingsMessage::DnsHijack,
            ),
            choice(
                state,
                strings.dns_mode,
                crate::i18n::dns_mode_label(config.dns.mode),
                &[DnsMode::FakeIp, DnsMode::Resolve, DnsMode::System]
                    .map(crate::i18n::dns_mode_label),
                SettingsMessage::NextDnsMode,
            ),
        ],
    );

    let proxy = section(
        state,
        strings.local_proxy,
        vec![
            switch(
                state,
                proxy_label(
                    strings.socks_proxy,
                    config.network.socks.as_ref(),
                    SOCKS_LISTEN,
                ),
                config.network.socks.is_some(),
                SettingsMessage::Socks,
            ),
            switch(
                state,
                proxy_label(
                    strings.http_proxy,
                    config.network.http.as_ref(),
                    HTTP_LISTEN,
                ),
                config.network.http.is_some(),
                SettingsMessage::Http,
            ),
        ],
    );

    let log = section(
        state,
        strings.log,
        vec![switch(
            state,
            strings.verbose_log,
            verbose(state),
            SettingsMessage::VerboseLog,
        )],
    );

    let updates = section(
        state,
        strings.updates,
        vec![
            switch(
                state,
                strings.check_updates,
                config.app.check_updates,
                SettingsMessage::CheckUpdates,
            ),
            update_row(state),
        ],
    );

    // Между разделами зазор больше, чем между строками.
    let body = Flex::col()
        .w(Size::FILL)
        .push_auto(startup)
        .push_auto(network)
        .push_auto(dns)
        .push_auto(proxy)
        .push_auto(log)
        .push_auto(updates)
        .gap(gap::MD)
        .build();

    table::sheet(
        &state.palette,
        table::scroll(body),
        crate::i18n::s().settings_hint,
    )
}

/// Журнал подробен: любой уровень от `debug` — «включено».
fn verbose(state: &State) -> bool {
    state.config.app.log_level >= penguin_config::schema::app::LogLevel::Debug
}

/// Заголовок раздела с чертой до края и строки под ним.
fn section<'a>(
    state: &'a State,
    title: &'a str,
    rows: Vec<Element<'a, Message>>,
) -> Element<'a, Message> {
    let palette = &state.palette;

    // Пробел после заголовка: вплотную черта читается подчёркиванием.
    let head = Flex::row()
        .w(Size::FILL)
        .push_auto(glyphs(
            format!("{title} "),
            ink::level(palette, ink::SECONDARY),
        ))
        .push(table::divider(palette))
        .gap(gap::NONE)
        .align(Alignment::Center)
        .build();

    Flex::col()
        .w(Size::FILL)
        .push_auto(head)
        .extend(rows)
        .gap(ROW_GAP)
        .build()
}

/// Строка переключателя: подпись слева, значение у правого края.
fn switch<'a>(
    state: &'a State,
    label: impl IntoFragment<'a>,
    enabled: bool,
    message: fn(bool) -> SettingsMessage,
) -> Element<'a, Message> {
    row(state, label, value(enabled), enabled, message(!enabled))
}

/// Строка выбора из нескольких: щелчок ставит следующее значение. Яркая всегда:
/// выключенного положения у неё нет.
fn choice<'a>(
    state: &'a State,
    label: &'a str,
    current: &str,
    options: &[&str],
    message: SettingsMessage,
) -> Element<'a, Message> {
    row(state, label, choice_value(current, options), true, message)
}

/// Значение выбора шириной в самое длинное из возможных.
fn choice_value(current: &str, options: &[&str]) -> String {
    let width = options.iter().map(|o| o.chars().count()).max().unwrap_or(0);
    format!("[ {} ]", pad(current, width))
}

/// Подпись слева, значение у правого края, нажимается вся строка.
fn row<'a>(
    state: &'a State,
    label: impl IntoFragment<'a>,
    value: String,
    bright: bool,
    message: SettingsMessage,
) -> Element<'a, Message> {
    let palette = &state.palette;

    // Включённое ярче: «что сейчас работает» видно боковым зрением.
    let (label_ink, value_ink) = if bright {
        (palette.text, palette.text)
    } else {
        (
            ink::level(palette, ink::SECONDARY),
            ink::level(palette, ink::TERTIARY),
        )
    };

    let line = Flex::row()
        .w(Size::FILL)
        .push_auto(glyphs(label, label_ink))
        .push(ui::spring())
        .push_auto(glyphs(value, value_ink))
        .gap(CELL)
        .align(Alignment::Center)
        .build();

    button(line)
        .width(Length::Fill)
        .padding(ROW_PADDING)
        .style(table::row_style(bright))
        .on_press(Message::Settings(message))
        .into()
}

/// «SOCKS5-прокси для приложений на 127.0.0.1:1080»: адрес — заданный в файле
/// или тот, что поставит включение.
fn proxy_label(label: &str, configured: Option<&InboundConfig>, fallback: SocketAddr) -> String {
    let listen = configured.map_or(fallback, |inbound| inbound.listen);
    format!("{label} {listen}")
}

/// Строка как у переключателей: версия слева, действие в скобках справа, нажимается вся.
fn update_row(state: &State) -> Element<'_, Message> {
    let palette = &state.palette;
    let status = &state.updates.status;
    let (label, message) = update_action(status);

    let tone = match status {
        UpdateStatus::Available(_) => palette.text,
        _ => ink::level(palette, ink::SECONDARY),
    };
    let value_tone = if message.is_some() {
        palette.text
    } else {
        ink::level(palette, ink::TERTIARY)
    };

    let line = Flex::row()
        .w(Size::FILL)
        .push_auto(glyphs(status_line(status), tone))
        .push(ui::spring())
        .push_auto(glyphs(format!("[ {label} ]"), value_tone))
        .gap(CELL)
        .align(Alignment::Center)
        .build();

    button(line)
        .width(Length::Fill)
        .padding(ROW_PADDING)
        .style(table::row_style(message.is_some()))
        .on_press_maybe(message.map(Message::Update))
        .into()
}

/// Что сделает нажатие на строку; пока занято — ничего.
fn update_action(status: &UpdateStatus) -> (&'static str, Option<UpdateMessage>) {
    let strings = crate::i18n::s();
    match status {
        UpdateStatus::Available(_) => (strings.update_install, Some(UpdateMessage::Install)),
        UpdateStatus::Checking | UpdateStatus::Installing | UpdateStatus::Restarting => {
            (strings.update_check, None)
        }
        UpdateStatus::Idle | UpdateStatus::Latest | UpdateStatus::Failed(_) => {
            (strings.update_check, Some(UpdateMessage::Check))
        }
    }
}

/// «Версия 0.7.2, доступна 0.8.0».
pub(crate) fn status_line(status: &UpdateStatus) -> String {
    let strings = crate::i18n::s();
    let version = penguin_update::Version::current();
    let tail = match status {
        UpdateStatus::Idle => return format!("{} {version}", strings.version),
        UpdateStatus::Latest => strings.update_latest.to_owned(),
        UpdateStatus::Checking => strings.update_checking.to_owned(),
        UpdateStatus::Available(found) => {
            format!("{} {}", strings.update_available, found.version)
        }
        UpdateStatus::Installing => strings.update_installing.to_owned(),
        UpdateStatus::Restarting => strings.update_restarting.to_owned(),
        UpdateStatus::Failed(reason) => format!("{} {reason}", strings.update_failed),
    };
    format!("{} {version}, {tail}", strings.version)
}

/// Значение в скобках; обе подписи одной ширины (по самим подписям: на другом
/// языке длина другая), иначе правый край прыгает.
fn value(enabled: bool) -> String {
    let strings = crate::i18n::s();
    let width = strings.on.chars().count().max(strings.off.chars().count());
    let label = if enabled { strings.on } else { strings.off };

    format!("[ {} ]", pad(label, width))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_with_defaults() {
        let _ = view(&State::default());
    }

    #[test]
    fn the_tab_fills_the_window() {
        let size = view(&State::default()).as_widget().size();
        assert_eq!(size.width, Length::Fill);
        assert_eq!(size.height, Length::Fill);
    }

    #[test]
    fn both_values_are_the_same_width() {
        assert_eq!(value(true).chars().count(), value(false).chars().count());
    }

    #[test]
    fn a_value_says_which_way_the_switch_is() {
        assert_ne!(value(true), value(false));
        assert!(value(true).contains(crate::i18n::s().on));
        assert!(value(false).contains(crate::i18n::s().off));
    }

    #[test]
    fn every_switch_is_named_by_what_it_does() {
        // Объяснений под переключателями нет: подпись — единственное, что сказано.
        for label in [
            crate::i18n::s().kill_switch,
            crate::i18n::s().allow_lan,
            crate::i18n::s().capture_default_route,
            crate::i18n::s().dns_hijack,
            crate::i18n::s().autostart,
            crate::i18n::s().autoconnect,
            crate::i18n::s().verbose_log,
            crate::i18n::s().check_updates,
            crate::i18n::s().language,
            crate::i18n::s().ipv6,
            crate::i18n::s().dns_mode,
            crate::i18n::s().socks_proxy,
            crate::i18n::s().http_proxy,
            #[cfg(target_os = "macos")]
            crate::i18n::s().dock_icon,
        ] {
            assert!(
                label.split_whitespace().count() > 2,
                "подпись `{label}` не объясняет настройку"
            );
        }
    }

    #[test]
    fn the_update_row_checks_installs_or_waits() {
        assert!(matches!(
            update_action(&UpdateStatus::Idle).1,
            Some(UpdateMessage::Check)
        ));
        assert!(update_action(&UpdateStatus::Checking).1.is_none());
        assert!(update_action(&UpdateStatus::Installing).1.is_none());
    }

    #[test]
    fn the_status_line_names_both_versions_when_one_is_offered() {
        let found = penguin_update::Available {
            version: "99.0.0".into(),
            page_url: String::new(),
            archive_name: String::new(),
            archive_url: String::new(),
            sums_url: String::new(),
        };
        let line = status_line(&UpdateStatus::Available(found));
        assert!(line.contains(&penguin_update::Version::current().to_string()));
        assert!(line.contains("99.0.0"), "{line}");
        assert!(status_line(&UpdateStatus::Failed("нет сети".into())).contains("нет сети"));
    }

    #[test]
    fn every_update_state_renders() {
        let mut state = State::default();
        for status in [
            UpdateStatus::Idle,
            UpdateStatus::Checking,
            UpdateStatus::Latest,
            UpdateStatus::Installing,
            UpdateStatus::Restarting,
            UpdateStatus::Failed("x".into()),
        ] {
            state.updates.status = status;
            let _ = view(&state);
        }
    }

    #[test]
    fn the_theme_is_not_offered_here() {
        // Тему переключает кружок в шапке.
        let state = State::default();
        let _ = view(&state);
    }

    #[test]
    fn nothing_here_waits_for_saving() {
        let state = State {
            dirty: true,
            ..State::default()
        };
        let _ = view(&state);
    }

    #[test]
    fn every_switch_renders_in_both_positions() {
        let mut state = State::default();
        for value in [true, false] {
            state.config.app.autostart = value;
            state.config.app.autoconnect = value;
            state.config.network.kill_switch = value;
            state.config.network.allow_lan = value;
            state.config.network.capture_default_route = value;
            state.config.dns.hijack = value;
            state.config.network.tun.ipv6_enabled = value;
            state.config.app.dock_icon = value;
            state.config.network.socks = value.then_some(InboundConfig {
                listen: SOCKS_LISTEN,
                auth: None,
            });
            state.config.network.http = value.then_some(InboundConfig {
                listen: HTTP_LISTEN,
                auth: None,
            });
            state.config.app.log_level = if value {
                penguin_config::schema::app::LogLevel::Debug
            } else {
                penguin_config::schema::app::LogLevel::Info
            };
            let _ = view(&state);
        }
    }

    #[test]
    fn every_dns_mode_renders() {
        let mut state = State::default();
        for mode in [DnsMode::FakeIp, DnsMode::Resolve, DnsMode::System] {
            state.config.dns.mode = mode;
            let _ = view(&state);
        }
    }

    #[test]
    fn a_choice_keeps_its_right_edge_in_place() {
        let options = ["FAKE-IP", "SYSTEM"];
        let long = choice_value("FAKE-IP", &options);
        let short = choice_value("SYSTEM", &options);
        assert_eq!(long.chars().count(), short.chars().count());
        assert!(short.contains("SYSTEM"), "{short}");
    }

    #[test]
    fn the_proxy_row_names_the_address_it_listens_on() {
        assert!(proxy_label("SOCKS5", None, SOCKS_LISTEN).ends_with("127.0.0.1:1080"));
        let custom = InboundConfig {
            listen: "127.0.0.1:2080".parse().expect("адрес"),
            auth: None,
        };
        assert!(proxy_label("SOCKS5", Some(&custom), SOCKS_LISTEN).ends_with(":2080"));
    }

    #[test]
    fn anything_more_detailed_than_info_reads_as_verbose() {
        use penguin_config::schema::app::LogLevel;

        let mut state = State::default();
        for level in [LogLevel::Error, LogLevel::Warn, LogLevel::Info] {
            state.config.app.log_level = level;
            assert!(!verbose(&state), "{level:?} — не подробный журнал");
        }
        for level in [LogLevel::Debug, LogLevel::Trace] {
            state.config.app.log_level = level;
            assert!(verbose(&state), "{level:?} — подробный журнал");
        }
    }
}
