//! Окно клиента без системной рамки: шапку и «светофор» рисует кит.
//!
//! Библиотека: исполняемый файл один, кем ему быть — решает `crates/app`.

#![allow(unreachable_pub)]

mod app;
mod console;
mod forms;
mod i18n;
mod ipc;
mod screens;
mod self_exec;
mod subscription;
mod theme;
mod tray;
mod ui;

use penguin_config::schema::app::Language;

/// Переменная окружения окна, запущенного после обновления: прежнее окно ещё
/// закрывается, и новое ждёт его места, а не уступает.
pub const RESTARTED: &str = "PENGUIN_RESTARTED";

/// Открывает окно и работает, пока его не закроют.
///
/// `hidden` — открыться сразу в лотке (автозапуск); без значка окно покажется.
pub fn run(hidden: bool) -> iced::Result {
    // Остаток прошлого обновления: на Windows прежний exe уходит в `.old`.
    penguin_update::remove_leftovers();

    let settings = penguin_config::ConfigStore::discover()
        .ok()
        .and_then(|store| store.load().ok());

    // Язык до первой отрисовки, иначе окно мигнёт чужим.
    i18n::set_language(settings.map_or(Language::Ru, |config| config.app.language));

    let theme = theme::load();

    iced::application(
        move || app::App::new(theme, hidden),
        app::App::update,
        app::App::view,
    )
    .title(app::App::title)
    .subscription(app::App::subscription)
    .theme(app::App::theme)
    // Без байтов шрифта iced молча возьмёт системный.
    .font(uikit::font::NERD_FONT_BYTES)
    .default_font(ui::FONT)
    // Заливку и углы рисует `uikit::window::Frame`.
    .style(|_state, theme: &iced::Theme| iced::theme::Style {
        background_color: iced::Color::TRANSPARENT,
        text_color: theme.palette().text,
    })
    .window(iced::window::Settings {
        size: uikit::window::frame::outer(app::COMPACT),
        icon: window_icon(),
        // Не показывать и прятать потом: окно бы мигнуло.
        visible: !hidden,
        // Размером владеет `Morph`. На Linux `true`: у winit на Wayland
        // `false` фиксирует min = max и панель не раскрывается.
        resizable: cfg!(target_os = "linux"),
        decorations: false,
        transparent: true,
        // Должно совпадать с `penguin.desktop` из `scripts/package.sh`.
        #[cfg(target_os = "linux")]
        platform_specific: iced::window::settings::PlatformSpecific {
            application_id: "penguin".to_owned(),
            ..Default::default()
        },
        ..iced::window::Settings::default()
    })
    .run()
}

/// Иконка окна; `None`, если не разобралась, — окно открывается и так.
pub(crate) fn window_icon() -> Option<iced::window::Icon> {
    iced::window::icon::from_file_data(include_bytes!("../../../assets/icon.ico"), None).ok()
}
