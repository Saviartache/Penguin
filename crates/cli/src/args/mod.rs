//! Разбор команд терминала без внешних библиотек.

mod command;
mod help;
mod lexer;

pub use command::{
    Command, DeployCommand, I2pdCommand, NAMES, ProfilesCommand, RulesCommand, SocksArgs,
    SubscriptionCommand, UpdateCommand, leaf, parse,
};
pub use lexer::{ArgsError, Lexer, Parsed, Token};
