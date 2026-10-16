//! Сопоставление по процессу: [`path`] (однозначно), [`name`] (имя может
//! совпасть с чужим файлом), [`set`] (оба с индексами).

mod glob;
pub mod name;
pub mod path;
pub mod set;

pub use name::NameSet;
pub use path::{GlobPathSet, PathSet, PrefixSet};
pub use set::{ProcessSet, ProcessSetBuilder};
