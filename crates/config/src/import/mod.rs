//! Чужие списки правил — в группы набора.

mod surge;

pub(crate) use surge::title;
pub use surge::{Imported, parse_surge};
