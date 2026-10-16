//! Собирает список фич, включённых в эту сборку, и отдаёт его коду.
//!
//! Для теста «фича включена — протокол зарегистрирован»: Cargo кладёт
//! `CARGO_FEATURE_<ИМЯ>` на каждую включённую фичу. `_` восстанавливается как
//! `-`, поэтому фичи с подчёркиванием в имени заводить нельзя.

fn main() {
    let mut features: Vec<String> = std::env::vars()
        .filter_map(|(name, _)| {
            name.strip_prefix("CARGO_FEATURE_")
                .map(|feature| feature.to_ascii_lowercase().replace('_', "-"))
        })
        .collect();
    features.sort_unstable();

    println!("cargo:rustc-env=PENGUIN_FEATURES={}", features.join(","));
    println!("cargo:rerun-if-changed=build.rs");
}
