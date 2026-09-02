//! Образец настроек, который уезжает в поставку, обязан разбираться.
//!
//! Отдельным тестом, а не глазами: файл лежит в `assets/`, его правят реже
//! кода, и ломается он молча — схема поехала, поле переименовали, действие
//! правила стало записываться иначе. Узнать об этом от пользователя, который
//! скопировал образец и получил отказ, — худший из возможных способов.

// Вспомогательные функции этого файла паникуют вместо возврата ошибки, и это
// здесь верное поведение: непрочитавшийся образец или не собравшийся набор
// правил — не «ошибка, которую надо обработать», а провалившийся тест. Запрет
// `expect` заведён ради горячего пути, где паника рвёт соединение; в тестах
// обход его через `if let` даёт тест, молча проходящий при поломке.
#![allow(clippy::expect_used)]

use std::path::PathBuf;

use penguin_config::{ConfigStore, RootConfig, SCHEMA_VERSION};

/// Путь к образцу от корня репозитория.
fn example_path() -> PathBuf {
    // `CARGO_MANIFEST_DIR` — это `crates/config`; корень на два уровня выше.
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
    // Разобраться и пройти проверку — разные вещи: неверная подсеть в правиле
    // разбирается, но набор правил из неё не собирается.
    penguin_config::validate::validate(&example()).expect("образец проходит проверку");
}

#[test]
fn the_shipped_example_has_something_to_show() {
    // Образец без профиля и без правил ничего не объясняет — а объяснять он и
    // нужен: в окне видно по одному экрану за раз, в файле — всё сразу.
    let config = example();

    assert!(!config.profiles.is_empty(), "нет ни одного профиля");
    assert!(!config.routing.rules.is_empty(), "нет ни одного правила");
    assert!(config.active().is_some(), "не понять, куда подключаться");
}
