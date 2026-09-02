//! Кто владеет соединением. Ответ на этот вопрос — половина раздельного
//! тоннелирования.
//!
//! Ключевое свойство крейта: **драйвер ядра не нужен**. TUN забирает трафик,
//! соединение собирается в пользовательском пространстве, и в этот момент
//! известен его локальный порт. По локальному порту систему можно спросить,
//! чей он, — и она ответит:
//!
//! | ОС | Как |
//! |---|---|
//! | Windows | `GetExtendedTcpTable` / `GetExtendedUdpTable`, затем `QueryFullProcessImageNameW` |
//! | Linux | `/proc/net/{tcp,udp}` -> inode сокета -> обход `/proc/*/fd` |
//! | macOS | `proc_pidfdinfo` |
//!
//! Ни своей подписи, ни возни с антивирусами, ни синего экрана от собственной
//! ошибки. Цена — гонка на очень коротких соединениях: владелец может
//! остаться неизвестным. Такое соединение **не блокируется**, а уходит по
//! умолчанию режима, потому что «не знаю чьё» и «ничьё» — разные вещи.

pub mod cache;
pub mod enumerate;
pub mod icon;
pub mod identity;
pub mod platform;
pub mod resolver;

pub use cache::IdentityCache;
pub use enumerate::{ProcessEnumerator, RunningApp, system_enumerator};
pub use identity::{ProcessIdentity, normalize_path};
pub use resolver::{FlowOwnerResolver, NoResolver, system_resolver};
