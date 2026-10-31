//! Развёртывание сервера Pingwin на чужой машине через системный `ssh`.
//!
//! Всё на сервере делает `servers/pingwin/docker/install.sh`: он вшит в файл
//! и уходит на stdin `ssh`. Запрос читается из stdin, а не из аргументов —
//! пароль не должен попасть в список процессов; `ssh` получает его через
//! [`crate::askpass`]. Пользователю не `root` нужен `sudo` без пароля.

pub mod event;
pub mod request;
pub mod run;
pub mod ssh;

pub use run::run;
