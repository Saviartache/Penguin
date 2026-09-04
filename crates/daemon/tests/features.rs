//! Набор протоколов у демона обязан совпадать с набором у движка.
//!
//! Перечисление фич в `crates/daemon/Cargo.toml` нужно ровно за одним:
//! `--no-default-features` должен собирать демона без единого протокола, а
//! включать их — по одному. Список этот ведётся руками и потому отстаёт: у
//! движка протокол появился, у демона фичу забыли, и выключить его нельзя.
//!
//! Собирается такое молча — оба манифеста верны сами по себе. Поэтому их
//! сверяет тест: он читает оба файла и сравнивает разделы `[features]`.
//!
//! Стрелка не нарушена: `daemon` и так зависит от `engine` (`AGENTS.md` §1).
//! Обратный тест — в движке про демона — был бы стрелкой вверх, пусть и в
//! проверке.

// Тест читает манифесты и падает, если их нет: непрочитавшийся файл — это не
// «ошибка, которую надо обработать», а провалившаяся проверка. Запрет `expect`
// заведён ради горячего пути, где паника рвёт соединение.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::PathBuf;

/// Имена фич из раздела `[features]` манифеста.
///
/// `default` отбрасывается: это не протокол, а перечисление остальных.
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
    // Разойдись они — и `penguin` из поставки собрался бы с одним набором
    // протоколов, а `cargo test` проверял бы другой.
    assert_eq!(default_of(ENGINE), default_of(DAEMON));
}

#[test]
fn the_default_set_holds_every_protocol() {
    // Протокол, собранный, но не включённый по умолчанию, не увидит никто,
    // кроме того, кто прочитал манифест.
    assert_eq!(default_of(ENGINE), features(ENGINE));
}

#[test]
fn feature_names_have_no_underscores() {
    // `build.rs` движка восстанавливает имя фичи из переменной среды Cargo, а
    // тот поднимает регистр и заменяет `-` на `_`. Обратная замена вернёт
    // дефис — и фича с настоящим подчёркиванием приедет туда под чужим именем.
    for name in features(ENGINE).iter().chain(features(DAEMON).iter()) {
        assert!(
            !name.contains('_'),
            "фича `{name}`: подчёркивание в имени, а `build.rs` вернёт дефис"
        );
    }
}
