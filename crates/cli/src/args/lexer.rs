//! Лексер аргументов: флаги, слова, значения флагов.

use std::fmt::Display;
use std::str::FromStr;
use std::vec::IntoIter;

use thiserror::Error;

/// Ошибка разбора аргументов.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArgsError {
    /// Неизвестная команда.
    #[error("неизвестная команда '{0}'")]
    UnknownCommand(String),
    /// Неизвестный флаг.
    #[error("неизвестный флаг '{0}'")]
    UnknownOption(String),
    /// Лишнее слово.
    #[error("лишний аргумент '{0}'")]
    Unexpected(String),
    /// У флага нет значения.
    #[error("для '{0}' не указано значение")]
    MissingValue(String),
    /// Флагу значение не положено.
    #[error("флаг '{0}' не принимает значение")]
    NoValue(String),
    /// Не указан обязательный аргумент.
    #[error("не указан аргумент {0}")]
    MissingArgument(&'static str),
    /// Не указана подкоманда группы.
    #[error("команде '{0}' нужна подкоманда")]
    MissingCommand(&'static str),
    /// Значение не разобралось.
    #[error("значение '{value}' для '{option}' не подходит: {reason}")]
    InvalidValue {
        /// Флаг.
        option: String,
        /// Что написали.
        value: String,
        /// Почему не разобралось.
        reason: String,
    },
    /// Аргумент не в UTF-8.
    #[error("аргумент не в UTF-8")]
    NotUnicode,
}

/// Итог разбора: запустить или напечатать текст (справка, версия).
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed<T> {
    /// Выполнить.
    Run(T),
    /// Напечатать и выйти.
    Print(&'static str),
}

impl<T> Parsed<T> {
    /// Преобразует результат запуска.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Parsed<U> {
        match self {
            Self::Run(value) => Parsed::Run(f(value)),
            Self::Print(text) => Parsed::Print(text),
        }
    }

    /// Продолжает разбор после запуска; печать проходит насквозь.
    pub fn and_then<U>(
        self,
        f: impl FnOnce(T) -> Result<Parsed<U>, ArgsError>,
    ) -> Result<Parsed<U>, ArgsError> {
        match self {
            Self::Run(value) => f(value),
            Self::Print(text) => Ok(Parsed::Print(text)),
        }
    }
}

/// Элемент командной строки.
#[derive(Debug, PartialEq, Eq)]
pub enum Token {
    /// `-x` или `--name`; `--name=значение` отдаёт значение через [`Lexer::value`].
    Flag(String),
    /// Всё остальное.
    Word(String),
}

/// Читает аргументы по одному.
pub struct Lexer {
    rest: IntoIter<String>,
    inline: Option<(String, String)>,
}

impl Lexer {
    /// Лексер над аргументами без имени программы.
    pub fn new(args: impl IntoIterator<Item = String>) -> Self {
        Self {
            rest: args.into_iter().collect::<Vec<_>>().into_iter(),
            inline: None,
        }
    }

    /// Следующий элемент.
    pub fn next_token(&mut self) -> Result<Option<Token>, ArgsError> {
        if let Some((flag, _)) = self.inline.take() {
            return Err(ArgsError::NoValue(flag));
        }
        let Some(arg) = self.rest.next() else {
            return Ok(None);
        };
        if !is_flag(&arg) {
            return Ok(Some(Token::Word(arg)));
        }
        match arg.split_once('=') {
            Some((flag, value)) if arg.starts_with("--") => {
                let flag = flag.to_owned();
                self.inline = Some((flag.clone(), value.to_owned()));
                Ok(Some(Token::Flag(flag)))
            }
            _ => Ok(Some(Token::Flag(arg))),
        }
    }

    /// Флаг в исходном виде (с `=значение`, если было) — для передачи дальше.
    pub fn passthrough(&mut self, flag: &str) -> String {
        match self.inline.take() {
            Some((_, value)) => format!("{flag}={value}"),
            None => flag.to_owned(),
        }
    }

    /// Значение флага: `--name=значение` или следующее слово.
    pub fn value(&mut self, flag: &str) -> Result<String, ArgsError> {
        if let Some((_, value)) = self.inline.take() {
            return Ok(value);
        }
        match self.rest.next() {
            Some(value) if !is_flag(&value) => Ok(value),
            _ => Err(ArgsError::MissingValue(flag.to_owned())),
        }
    }

    /// Значение флага, разобранное в `T`.
    pub fn parsed<T>(&mut self, flag: &str) -> Result<T, ArgsError>
    where
        T: FromStr,
        T::Err: Display,
    {
        let value = self.value(flag)?;
        value
            .parse()
            .map_err(|err: T::Err| ArgsError::InvalidValue {
                option: flag.to_owned(),
                reason: err.to_string(),
                value,
            })
    }
}

/// Флаг ли это; одиночный `-` — слово.
fn is_flag(arg: &str) -> bool {
    arg.len() > 1 && arg.starts_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lexer(args: &[&str]) -> Lexer {
        Lexer::new(args.iter().map(|arg| (*arg).to_owned()))
    }

    #[test]
    fn splits_flags_and_words() {
        let mut lx = lexer(&["word", "-p", "--long", "-"]);
        assert_eq!(lx.next_token(), Ok(Some(Token::Word("word".into()))));
        assert_eq!(lx.next_token(), Ok(Some(Token::Flag("-p".into()))));
        assert_eq!(lx.next_token(), Ok(Some(Token::Flag("--long".into()))));
        assert_eq!(lx.next_token(), Ok(Some(Token::Word("-".into()))));
        assert_eq!(lx.next_token(), Ok(None));
    }

    #[test]
    fn value_follows_or_is_inline() {
        let mut lx = lexer(&["--a", "1", "--b=2"]);
        lx.next_token().expect("флаг");
        assert_eq!(lx.value("--a").as_deref(), Ok("1"));
        lx.next_token().expect("флаг");
        assert_eq!(lx.value("--b").as_deref(), Ok("2"));
    }

    #[test]
    fn value_is_required() {
        let mut lx = lexer(&["--a", "--b"]);
        lx.next_token().expect("флаг");
        assert_eq!(lx.value("--a"), Err(ArgsError::MissingValue("--a".into())));
    }

    #[test]
    fn passthrough_restores_the_inline_value() {
        let mut lx = lexer(&["--a=1", "--b"]);
        lx.next_token().expect("флаг");
        assert_eq!(lx.passthrough("--a"), "--a=1");
        lx.next_token().expect("флаг");
        assert_eq!(lx.passthrough("--b"), "--b");
    }

    #[test]
    fn inline_value_on_a_switch_is_rejected() {
        let mut lx = lexer(&["--udp=1"]);
        lx.next_token().expect("флаг");
        assert_eq!(lx.next_token(), Err(ArgsError::NoValue("--udp".into())));
    }

    #[test]
    fn bad_value_names_the_flag() {
        let mut lx = lexer(&["--n", "x"]);
        lx.next_token().expect("флаг");
        let err = lx.parsed::<u16>("--n").expect_err("не число");
        assert!(matches!(err, ArgsError::InvalidValue { ref option, .. } if option == "--n"));
    }
}
