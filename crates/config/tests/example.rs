//! Образец настроек из поставки обязан разбираться и проходить проверку.

#![allow(clippy::expect_used)] // Паника в тесте — это провал

use std::path::PathBuf;

use penguin_config::{ConfigStore, RootConfig, SCHEMA_VERSION};

/// Путь к образцу от корня репозитория.
fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/config.example.toml")
}

/// Читает и разбирает образец.
fn example() -> RootConfig {
    let path = example_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("образец не читается ({}): {err}", path.display()));

    ConfigStore::parse(&raw, &path).expect("образец разбирается")
}

#[test]
fn the_shipped_example_parses() {
    let config = example();
    assert_eq!(
        config.version, SCHEMA_VERSION,
        "образец от другой версии схемы"
    );
}

#[test]
fn the_shipped_example_is_valid() {
    penguin_config::validate::validate(&example()).expect("образец проходит проверку");
}

#[test]
fn the_shipped_example_has_something_to_show() {
    let config = example();

    assert!(!config.profiles.is_empty(), "нет ни одного профиля");
    assert!(!config.routing.rules.is_empty(), "нет ни одного правила");
    assert!(config.active().is_some(), "не понять, куда подключаться");
}
