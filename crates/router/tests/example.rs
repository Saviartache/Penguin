//! Правила образца настроек должны не только разбираться, но и решать:
//! игры напрямую, их патчи через тоннель.

// В тестах паника вместо ошибки уместна
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
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/config.example.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("образец не читается ({}): {err}", path.display()));

    ConfigStore::parse(&raw, &path).expect("образец разбирается")
}

/// Собирает маршрутизатор как клиент при запуске.
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
    assert_eq!(router().rule_count(), example().routing.rules.len());
}

#[test]
fn the_example_keeps_its_promise_about_games() {
    let router = router();

    assert_eq!(
        decide(&router, "203.0.113.10:27015", "steam.exe"),
        ResolvedDecision::Direct,
        "игра ушла в тоннель"
    );

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
    let router = router();

    let by_address = decide(&router, "steamcontent.com:443", "steam.exe");
    let by_process = decide(&router, "steamcontent.com:443", "chrome.exe");

    assert!(matches!(by_address, ResolvedDecision::Tunnel(_)));
    assert!(
        matches!(by_process, ResolvedDecision::Tunnel(_)),
        "у другого приложения тот же домен решается умолчанием режима"
    );

    assert_eq!(
        decide(&router, "203.0.113.10:27015", "steam.exe"),
        ResolvedDecision::Direct
    );
}
