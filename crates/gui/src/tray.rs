//! Значок в лотке: единственный способ достать скрытое окно, тоннель при этом
//! держит служба. Значок, меню и события — забота кита ([`uikit::tray`]).

use uikit::tray::{Item, Tray};

/// Пункт «показать окно»: на Linux щелчок по значку событием не приходит.
pub const SHOW: &str = "show";

/// Пункт «выход» — как красный кружок: с остановкой службы.
pub const QUIT: &str = "quit";

/// Заводит значок; `None` — лотка нет или значок не создался (не сбой).
pub fn create() -> Option<Tray> {
    let strings = crate::i18n::s();
    let menu = vec![
        Item::new(SHOW, strings.tray_show),
        Item::separator(),
        Item::new(QUIT, strings.tray_quit),
    ];

    match Tray::monochrome(icon()?, crate::app::TITLE, menu) {
        Ok(tray) => Some(tray),
        Err(err) => {
            tracing::warn!(%err, "значка в лотке не будет");
            None
        }
    }
}

/// Чёрная маска; macOS красит её сама, остальным — цвет под панель.
fn icon() -> Option<iced::window::Icon> {
    let mask = iced::window::icon::from_file_data(include_bytes!("../../../assets/tray.png"), None);
    let mask = match mask {
        Ok(mask) => mask,
        Err(err) => {
            tracing::warn!(%err, "значок лотка не разобрался");
            return None;
        }
    };
    if cfg!(target_os = "macos") || light_panel() {
        return Some(mask);
    }

    let (mut rgba, size) = mask.into_raw();
    for pixel in rgba.as_chunks_mut::<4>().0 {
        pixel[..3].fill(u8::MAX);
    }
    iced::window::icon::from_rgba(rgba, size.width, size.height).ok()
}

/// Светлая ли панель, где стоит значок. Темы панели Linux не сообщает, а
/// верхняя панель GNOME тёмная.
fn light_panel() -> bool {
    #[cfg(windows)]
    {
        penguin_platform::appearance::light_taskbar()
    }
    #[cfg(not(windows))]
    {
        false
    }
}
