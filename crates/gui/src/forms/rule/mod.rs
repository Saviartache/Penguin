//! Группа правил в форме: черновик, сборка правила и обратный путь.

mod draft;
mod load;

pub use draft::{Action, Draft, HostKind, Section, host_kind, unique_id};
pub use load::load;
