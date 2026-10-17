//! Разбор команд терминала без внешних библиотек.

mod command;
mod help;
mod lexer;

pub use command::{
    Command, NAMES, ProfilesCommand, RulesCommand, SocksArgs, UpdateCommand, leaf, parse,
};
pub use lexer::{ArgsError, Lexer, Parsed, Token};
