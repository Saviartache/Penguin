//! Значок окна в Dock macOS.

use objc2::MainThreadMarker;
use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};

use crate::{PlatformError, PlatformResult};

/// Показывает или убирает значок в Dock; значок в строке меню остаётся.
///
/// Вызывать с главного потока: `NSApplication` с других не трогают.
pub fn set_visible(visible: bool) -> PlatformResult<()> {
    let main = MainThreadMarker::new().ok_or(PlatformError::Unsupported(
        "Dock меняется только с главного потока",
    ))?;
    let policy = if visible {
        NSApplicationActivationPolicy::Regular
    } else {
        NSApplicationActivationPolicy::Accessory
    };
    if NSApplication::sharedApplication(main).setActivationPolicy(policy) {
        Ok(())
    } else {
        Err(PlatformError::Unsupported(
            "политика активации не сменилась",
        ))
    }
}
