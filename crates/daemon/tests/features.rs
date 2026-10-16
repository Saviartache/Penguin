//! Набор протоколов у демона обязан совпадать с набором у движка.
//!
//! Список фич ведётся руками; тест сверяет разделы `[features]` двух манифестов,
//! иначе протокол движка нельзя включить по одному.

// Тест, не горячий путь
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::PathBuf;

/// Имена фич из раздела `[features]` манифеста.
///
/// Без `default`.
fn features(manifest: &str) -> BTreeSet<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(manifest);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("манифест не читается ({}): {err}", path.display()));
    let parsed: toml::Value = raw
        .parse()
        .unwrap_or_else(|err| panic!("{} не разбирается: {err}", path.display()));

    parsed
        .get("features")
        .and_then(toml::Value::as_table)
        .map(|table| {
            table
                .keys()
                .filter(|name| *name != "default")
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Что перечислено в `default`.
fn default_of(manifest: &str) -> BTreeSet<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(manifest);
    let raw = std::fs::read_to_string(&path).expect("манифест читается");
    let parsed: toml::Value = raw.parse().expect("манифест разбирается");

    parsed
        .get("features")
        .and_then(|features| features.get("default"))
        .and_then(toml::Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

const DAEMON: &str = "Cargo.toml";
const ENGINE: &str = "../engine/Cargo.toml";

#[test]
fn every_protocol_of_the_engine_can_be_switched_off_in_the_daemon() {
    let engine = features(ENGINE);
    let daemon = features(DAEMON);

    let missing: Vec<&String> = engine.difference(&daemon).collect();
    assert!(
        missing.is_empty(),
        "у движка есть фичи, которых нет у демона: {missing:?} — \
         значит, эти протоколы нельзя ни выключить, ни включить по одному"
    );

    let extra: Vec<&String> = daemon.difference(&engine).collect();
    assert!(
        extra.is_empty(),
        "у демона есть фичи, которых нет у движка: {extra:?} — \
         такая фича не включает ничего и молчит об этом"
    );
}

#[test]
fn the_default_set_is_the_same_on_both_sides() {
    assert_eq!(default_of(ENGINE), default_of(DAEMON));
}

#[test]
fn the_default_set_holds_every_protocol() {
    assert_eq!(default_of(ENGINE), features(ENGINE));
}

#[test]
fn feature_names_have_no_underscores() {
    // `build.rs` восстанавливает имя из env Cargo (`_` -> `-`)
    for name in features(ENGINE).iter().chain(features(DAEMON).iter()) {
        assert!(
            !name.contains('_'),
            "фича `{name}`: подчёркивание в имени, а `build.rs` вернёт дефис"
        );
    }
}
