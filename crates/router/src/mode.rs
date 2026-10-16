//! Режим тоннелирования. Тип живёт в [`penguin_config::schema::routing::TunnelMode`];
//! здесь [`crate::engine::default_decision`] — исход без совпавших правил.
//! Режим — только умолчание, порядок правил разбирает [`crate::ruleset::order`].

pub use penguin_config::schema::routing::TunnelMode;

pub use crate::engine::default_decision;
