//! Свой i2pd: маршрутизатор I2P для протокола `i2p` (`AGENTS.md` §1.11).
//!
//! В сборку не входит: окно качает выпуск из релиза `i2pd-<версия>` этого же
//! репозитория (`penguin i2pd install`), служба сверяет его с [`release`] и
//! кладёт к себе. Подменить файл, который служба запустит, нельзя: сумма
//! закреплена здесь, а не берётся из релиза.
//!
//! ```text
//!  движок ── i2pd ─(ntcp2.proxy, reseed.proxy)─► bypass: SOCKS5 127.0.0.1 ─► прямой выход
//!     ▲         │
//!     └─ протокол i2p ─ HTTP-прокси 127.0.0.1:4444
//! ```
//!
//! Весь трафик i2pd идёт в [`bypass`], а не в сеть: петля на loopback в TUN не
//! попадает, поэтому i2pd не уходит сам в себя, и это не зависит от поиска
//! владельца соединения в TUN.
//!
//! - Reseed не проверяется подписью: сертификатов в поставке нет (умолчание i2pd).
//! - На Unix i2pd работает от `nobody`; на Windows — от учётной записи службы.

pub mod account;
pub mod bypass;
pub mod conf;
pub mod error;
pub mod install;
pub mod progress;
pub mod release;
pub mod sidecar;

pub use error::{I2pdError, I2pdResult};
pub use progress::Progress;
pub use release::Build;
pub use sidecar::Sidecar;
