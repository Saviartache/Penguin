//! Сопоставление по процессу.
//!
//! Три способа назвать приложение, и они не равноценны:
//!
//! - [`path`] — путь: точный, каталогом или шаблоном. Однозначно;
//! - [`name`] — имя файла. Удобно писать, но так же называется любой файл,
//!   который кто-то положил рядом;
//! - [`set`] — то и другое вместе, с индексами под быструю проверку.

pub mod name;
pub mod path;
pub mod set;

pub use name::NameSet;
pub use path::{GlobPathSet, PathSet, PrefixSet};
pub use set::{ProcessSet, ProcessSetBuilder};
