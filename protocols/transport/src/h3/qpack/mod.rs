//! QPACK без динамической таблицы (RFC 9204).
//!
//! Статическая таблица, литералы и Хаффман; потоков кодировщика и декодировщика нет.
//!
//! ```text
//!  static_table  99 записей из приложения A
//!  huffman       код из RFC 7541, приложение B
//!  primitive     целое с префиксом и строка
//!  field         блок полей: префикс и представления
//! ```

mod error;
pub mod field;
pub mod huffman;
pub mod primitive;
pub mod static_table;

pub use error::QpackError;
pub use field::Field;
