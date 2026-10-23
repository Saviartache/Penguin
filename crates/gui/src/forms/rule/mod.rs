//! Группа правил в форме: черновик, сборка правила и обратный путь.

mod draft;
mod host;
mod load;

pub use draft::{Action, Draft, Section, unique_id};
pub use host::{HostKind, host_kind};
pub use load::load;
