//! Трейт `Matcher` и его результат.

use crate::target::MatchTarget;

/// Условие, подходящее соединению или нет. Без ввода-вывода: всё нужное лежит в [`MatchTarget`].
pub trait Matcher: Send + Sync + 'static {
    /// Подходит ли.
    fn matches(&self, target: &MatchTarget<'_>) -> bool;

    /// Короткое описание для объяснения решения в интерфейсе.
    fn describe(&self) -> String;
}
