//! Окно клиента.
//!
//! Окно **без системной рамки**: шапку, «светофор» и уголок изменения размера
//! рисует кит (`AGENTS.md` кита §3.2). Отсюда `decorations: false` — это не
//! украшение, а условие того, что все приложения на этом ките выглядят одним
//! семейством.
//!
//! Библиотека, а не программа: в поставке один исполняемый файл, и кем ему
//! быть, решает он сам по своим аргументам (`crates/app`).

// В крейте окна `pub` не образует публичного API за пределами самого окна: он
// лишь открывает элемент соседним модулям.
#![allow(unreachable_pub)]

mod app;
mod ascii;
mod forms;
mod i18n;
mod ipc;
mod screens;
mod theme;
mod ui;

use iced::{Application, Settings};
use penguin_config::schema::app::Language;

/// Открывает окно и работает, пока его не закроют.
pub fn run() -> iced::Result {
    let settings = penguin_config::ConfigStore::discover()
        .ok()
        .and_then(|store| store.load().ok());

    // Язык — до первой отрисовки: ответ службы придёт после неё, и окно
    // успело бы мигнуть чужим языком.
    i18n::set_language(settings.map_or(Language::Ru, |config| config.app.language));

    // Тема читается из своего файла: он лежит отдельно именно затем, чтобы
    // окно открылось в той теме, в которой его закрыли, даже если ни служба,
    // ни настройки недоступны (см. [`theme`]).
    let theme = theme::load();

    app::App::run(Settings {
        window: iced::window::Settings {
            size: app::COMPACT,
            // Размером владеет `Morph`, и владеет им один. Системное
            // растягивание завело бы второй источник размера, и они начали бы
            // спорить: окно раздувалось бы и съёживалось на глазах.
            resizable: false,
            // Рамку рисует кит: своя шапка и системная одновременно — это две
            // шапки одна над другой.
            decorations: false,
            ..iced::window::Settings::default()
        },
        // Флаги — тема: больше `Application::new` ничего не ждёт, всё
        // остальное приезжает от службы.
        flags: theme,
        ..Settings::default()
    })
}
