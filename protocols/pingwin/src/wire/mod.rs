//! Формат провода, общий с сервером: `keys` (ключи), `auth` (опознание), `udp` (датаграммы),
//! `capsule` (датаграммы в потоке HTTP/2), `tcp` (настройки HTTP/2).

pub mod auth;
pub mod capsule;
pub mod keys;
pub mod tcp;
pub mod udp;
