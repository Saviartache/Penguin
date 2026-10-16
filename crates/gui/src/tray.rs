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

    match Tray::new(crate::window_icon()?, crate::app::TITLE, menu) {
        Ok(tray) => Some(tray),
        Err(err) => {
            tracing::warn!(%err, "значка в лотке не будет");
            None
        }
    }
}
