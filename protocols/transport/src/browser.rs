//! Как представляется браузер в заголовках HTTP — как у Xray
//! (`common/utils/browser.go`).
//!
//! Версию Chrome Xray выводит из даты и процессора, начиная со 144; здесь
//! стоит опорная 144: серверу всё равно, а наблюдателю сойдёт.

/// Версия Chrome.
pub const CHROME_VERSION: &str = "144";

/// `User-Agent` Chrome (`ChromeUA`).
pub const CHROME_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                                     AppleWebKit/537.36 (KHTML, like Gecko) \
                                     Chrome/144.0.0.0 Safari/537.36";
