//! Сервер протокола Pingwin: HTTP/3 по UDP и HTTP/2 по TCP, опознание, статическое прикрытие.
//!
//! ```text
//!  config      настройки: где слушать, чей ключ, какой сертификат, кого пускать
//!  tls         QUIC и TLS по TCP по файлам сертификата
//!  policy      таблица пользователей
//!  admission   опознание запроса (общее)
//!  server      приём соединений
//!  connection  одно соединение HTTP/3: опознание, запросы, датаграммы
//!  relay       CONNECT и канал датаграмм HTTP/3
//!  tcp/        то же по HTTP/2
//!  target      TCP и UDP до цели (общее)
//!  cover       прикрытие: статический сайт для тех, кого не узнали
//! ```
//!
//! Отдельная программа (`AGENTS.md` §1.6); библиотека — чтобы проверять приём тестом.

mod admission;
pub mod config;
mod connection;
pub mod cover;
pub mod policy;
pub mod relay;
pub mod server;
mod target;
mod tcp;
pub mod tls;

pub use config::{ServerConfig, User};
pub use policy::Policy;
pub use server::Server;
