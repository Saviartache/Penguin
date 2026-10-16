//! Рассинхронизация DPI: первая посылка уходит так, что её разберёт сервер, а не DPI по пути.
//!
//! Приёмы из `zapret2` (`github.com/bol-van/zapret2`), только те, что доступны из
//! пространства пользователя (как у `tpws`); приёмы на сырых пакетах не поддерживаются.
//! Ложную посылку протокол обязан выбирать такой, чтобы сервер её пропустил: малый TTL
//! не гарантирует, что она не дойдёт.
//!
//! | Приём `zapret2`   | Здесь                    |
//! | ----------------- | ------------------------ |
//! | `multisplit`      | [`Strategy::Multisplit`] |
//! | `multidisorder`   | [`Strategy::Disorder`]   |
//! | `fake`            | [`Strategy::Fake`]       |
//! | `fakedsplit`      | [`Strategy::FakedSplit`] |

pub mod plan;
pub mod write;

pub use plan::{
    DEFAULT_TTL, Desync, DesyncConfig, FOOLING_PAUSE, Marker, Position, Step, Strategy,
};
