//! Обновление с GitHub: проверка последнего релиза, сверка SHA-256, подмена исполняемого файла.
//!
//! Без сети (`default-features = false`) крейт — чистая логика: версии, разбор ответа API,
//! выбор поставки, `SHA256SUMS`, чтение архивов. Такую часть берёт окно:
//! в сеть оно не ходит, это делает `penguin update` (фича `net`).

mod archive;
mod checksum;
mod error;
mod flow;
#[cfg(feature = "net")]
mod net;
#[cfg(feature = "net")]
mod online;
mod release;
mod replace;
mod target;
mod version;

pub use error::{UpdateError, UpdateResult};
pub use flow::install_archive;
#[cfg(feature = "net")]
pub use online::{check, install, repository_url};
pub use release::{Available, CheckReport, find_update};
pub use replace::{remove_leftovers, replace_executable};
pub use target::{Format, Target};
pub use version::Version;
