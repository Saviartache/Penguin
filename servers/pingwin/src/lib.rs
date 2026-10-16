//! Сервер протокола Pingwin: HTTP/3, опознание, статическое прикрытие.
//!
//! ```text
//!  config      настройки: где слушать, чей ключ, какой сертификат, кого пускать
//!  tls         QUIC сервера по файлам сертификата
//!  policy      таблица пользователей
//!  server      приём соединений
//!  connection  одно соединение: опознание, запросы, датаграммы
//!  relay       что делать с CONNECT и каналом датаграмм
//!  cover       прикрытие: статический сайт для тех, кого не узнали
//! ```
//!
//! Отдельная программа (`AGENTS.md` §1.6); библиотека — чтобы проверять приём тестом.

pub mod config;
mod connection;
pub mod cover;
pub mod policy;
pub mod relay;
pub mod server;
pub mod tls;

pub use config::{ServerConfig, User};
pub use policy::Policy;
pub use server::Server;
