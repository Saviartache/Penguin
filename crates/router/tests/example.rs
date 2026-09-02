//! Правила из образца настроек обязаны не только разбираться, но и решать.
//!
//! Разбор образца проверяет `penguin-config`; здесь проверяется то, чего он
//! проверить не может — маршрутизатор в его зависимостях стоять не должен.
//!
//! Проверяется не «правила собрались», а **обещание образца**: игры идут
//! напрямую, а их патчи — через тоннель. Это два правила, разведённые
//! приоритетом, и переставить их местами можно ровно одной опечаткой.

// Вспомогательные функции этого файла паникуют вместо возврата ошибки, и это
// здесь верное поведение: непрочитавшийся образец или не собравшийся набор
// правил — не «ошибка, которую надо обработать», а провалившийся тест. Запрет
// `expect` заведён ради горячего пути, где паника рвёт соединение; в тестах
// обход его через `if let` даёт тест, молча проходящий при поломке.
#![allow(clippy::expect_used)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use penguin_config::{ConfigStore, RootConfig};
use penguin_core::id::OutboundId;
use penguin_core::network::Network;
use penguin_process::identity::ProcessIdentity;
use penguin_router::context::FlowContext;
use penguin_router::decision::ResolvedDecision;
use penguin_router::engine::Router;
use penguin_router::ruleset::CompileContext;

/// Читает образец из поставки.
fn example() -> RootConfig {
    // `CARGO_MANIFEST_DIR` — это `crates/router`; корень на два уровня выше.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/config.example.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("образец не читается ({}): {err}", path.display()));

    ConfigStore::parse(&raw, &path).expect("образец разбирается")
}

/// Собирает маршрутизатор ровно так, как это делает клиент при запуске.
fn router() -> Router {
    let config = example();
    Router::new(
        &config.routing,
        OutboundId::direct(),
        &CompileContext::default(),
    )
    .expect("набор правил собирается")
}

/// Куда уйдёт соединение от такого приложения к такому адресу.
fn decide(router: &Router, destination: &str, process: &str) -> ResolvedDecision {
    let flow = FlowContext::to_target(
        Network::Tcp,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        destination.parse().expect("адрес разбирается"),
    )
    .with_process(ProcessIdentity::new(0, process));

    router.resolve(&flow).decision
}

#[test]
fn every_example_rule_compiles() {
    // Правило, которое не собирается, — это правило, которое не работает, а
    // трафик идёт не туда.
    assert_eq!(router().rule_count(), example().routing.rules.len());
}

#[test]
fn the_example_keeps_its_promise_about_games() {
    let router = router();

    // Игровой трафик — напрямую: в нём важна задержка, и лишний узел на пути
    // портит ровно то, ради чего в игру и заходят.
    assert_eq!(
        decide(&router, "203.0.113.10:27015", "steam.exe"),
        ResolvedDecision::Direct,
        "игра ушла в тоннель"
    );

    // Патчи того же Steam — в тоннель: здесь важна скорость, и ради неё
    // протокол и существует. Правила разведены приоритетом, и поменять их
    // местами можно одной опечаткой.
    assert!(
        matches!(
            decide(&router, "steamcontent.com:443", "steam.exe"),
            ResolvedDecision::Tunnel(_)
        ),
        "патчи ушли мимо тоннеля"
    );
}

#[test]
fn the_local_network_never_goes_through_the_tunnel() {
    // Принтер и роутер за тоннелем — это неработающий принтер и роутер.
    let router = router();

    for address in ["192.168.1.10:445", "10.0.0.5:80", "127.0.0.1:8080"] {
        assert_eq!(
            decide(&router, address, "explorer.exe"),
            ResolvedDecision::Direct,
            "{address} ушёл не напрямую"
        );
    }
}

#[test]
fn an_unlisted_application_follows_the_mode() {
    // Режим — это только умолчание для того, о чём правила молчат; в образце
    // он `full`, то есть «всё остальное в тоннель».
    assert!(
        matches!(
            decide(&router(), "example.com:443", "chrome.exe"),
            ResolvedDecision::Tunnel(_)
        ),
        "трафик без правила ушёл мимо тоннеля при режиме `full`"
    );
}

#[test]
fn the_same_application_can_go_both_ways() {
    // Ради этого раздельное тоннелирование и нужно: решение зависит не от
    // приложения и не от адреса по отдельности, а от них вместе.
    let router = router();

    let by_address = decide(&router, "steamcontent.com:443", "steam.exe");
    let by_process = decide(&router, "steamcontent.com:443", "chrome.exe");

    assert!(matches!(by_address, ResolvedDecision::Tunnel(_)));
    assert!(
        matches!(by_process, ResolvedDecision::Tunnel(_)),
        "у другого приложения тот же домен решается умолчанием режима"
    );

    // А вот тот же Steam на другом адресе — уже напрямую.
    assert_eq!(
        decide(&router, "203.0.113.10:27015", "steam.exe"),
        ResolvedDecision::Direct
    );
}
