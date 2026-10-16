//! Группа правил в форме: черновик, сборка правила и обратный путь.

mod draft;
mod load;

pub use draft::{Action, Draft, unique_id};
pub use load::load;
