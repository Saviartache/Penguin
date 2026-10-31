//! HTTP/2 поверх TCP: настройки обеих сторон. Окна — как у Chrome: он так же
//! качает по одному соединению, и с ними скорость не упирается в 64 КиБ RFC.

/// Окно потока (`SETTINGS_INITIAL_WINDOW_SIZE` Chrome).
pub const STREAM_WINDOW: u32 = 6 * 1024 * 1024;

/// Окно соединения (Chrome шлёт `WINDOW_UPDATE` до 15 МиБ).
pub const CONNECTION_WINDOW: u32 = 15 * 1024 * 1024;

/// Таблица заголовков (`SETTINGS_HEADER_TABLE_SIZE` Chrome).
pub const HEADER_TABLE: u32 = 64 * 1024;

/// Предел списка заголовков (`SETTINGS_MAX_HEADER_LIST_SIZE` Chrome).
pub const MAX_HEADER_LIST: u32 = 256 * 1024;

/// Сколько записанного держать в очереди потока, пока окно занято.
pub const SEND_BUFFER: usize = 1024 * 1024;
