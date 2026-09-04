//! Локальный SOCKS5 поверх выбранного профиля — без TUN и без прав
//! администратора.
//!
//! Самая полезная команда на этапе отладки и вполне рабочий режим сам по себе.
//! Она поднимает всю цепочку клиента, кроме перехвата трафика:
//!
//! ```text
//!   приложение ──► SOCKS5 ──► маршрутизатор ──► протокол ──► сервер
//! ```
//!
//! Всё, чего здесь нет, — это TUN. Значит, нет ни драйвера, ни маршрутов, ни
//! брандмауэра, ни требования прав. Если через эту команду трафик ходит, а
//! через тоннель нет — проблема заведомо не в протоколе.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use penguin_config::RootConfig;
use penguin_config::schema::profile::Profile;
use penguin_config::schema::routing::TunnelMode;
use penguin_core::id::OutboundId;
use penguin_engine::direct::SystemDialer;
use penguin_engine::metrics::counters::Metrics;
use penguin_engine::outbounds::OutboundPool;
use penguin_engine::pipeline::Pipeline;
use penguin_inbound::inbound::Inbound;
use penguin_inbound::socks5::auth::Credentials;
use penguin_inbound::{HttpInbound, Socks5Inbound};
use penguin_router::engine::Router;
use penguin_router::ruleset::CompileContext;
use tokio_util::sync::CancellationToken;

use crate::args::SocksArgs;

/// Какой прокси поднимать.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// SOCKS5.
    Socks5,
    /// HTTP с методом CONNECT.
    Http,
}

/// Поднимает локальный прокси и работает, пока не прервут.
pub async fn run(config: &RootConfig, args: &SocksArgs, kind: Kind) -> Result<()> {
    let profile = pick_profile(config, args.profile.as_deref())?;

    // Разрешатель загрузочный, а не системный. «TUN не поднят, значит система
    // ответит честно» — рассуждение неверное: подмена DNS от прошлого запуска
    // переживает и тоннель, и сам клиент, и системный резолвер отвечает на имя
    // сервера подставным адресом (см. [`penguin_dns::bootstrap`]).
    let dialer = Arc::new(SystemDialer::new(penguin_dns::bootstrap::resolver_for(
        &config.dns,
    )));
    let outbounds = Arc::new(OutboundPool::new(dialer));

    outbounds
        .validate(profile)
        .with_context(|| format!("настройки профиля `{}`", profile.id))?;

    println!("Подключение к профилю `{}`…", profile.name);
    let outbound = outbounds
        .get_or_connect(profile)
        .await
        .with_context(|| format!("не удалось подключиться к профилю `{}`", profile.id))?;

    let active = OutboundId::from(profile.id.clone());
    let router = if args.no_rules {
        // Отделяет протокол от маршрутизации: если так трафик ходит, а с
        // правилами нет — дело в правилах.
        println!("Правила выключены: весь трафик идёт в тоннель.");
        Arc::new(Router::passthrough(TunnelMode::Full, active.clone()))
    } else {
        Arc::new(
            Router::new(&config.routing, active.clone(), &CompileContext::default())
                .context("не удалось собрать правила")?,
        )
    };

    // Владелец соединения ищется, только если правила по процессам вообще
    // есть: чтение таблицы соединений стоит системного вызова на каждое новое
    // соединение.
    let processes: Arc<dyn penguin_process::resolver::FlowOwnerResolver> =
        if config.routing.resolve_process && !args.no_rules {
            Arc::from(penguin_process::resolver::system_resolver())
        } else {
            Arc::new(penguin_process::resolver::NoResolver)
        };

    let metrics = Metrics::new();
    let pipeline = Arc::new(
        Pipeline::new(
            Arc::clone(&router),
            Arc::clone(&outbounds),
            processes,
            Arc::clone(&metrics),
        )
        .with_process_lookup(config.routing.resolve_process && !args.no_rules),
    );

    let credentials = credentials_for(config, kind);
    let cancel = CancellationToken::new();

    let inbound: Box<dyn Inbound> = match kind {
        Kind::Socks5 => Box::new(
            Socks5Inbound::bind(args.listen, pipeline, credentials)
                .await
                .with_context(|| format!("не удалось занять адрес {}", args.listen))?,
        ),
        Kind::Http => Box::new(
            HttpInbound::bind(args.listen, pipeline)
                .await
                .with_context(|| format!("не удалось занять адрес {}", args.listen))?,
        ),
    };

    let name = inbound.name();
    println!(
        "{name} слушает на {} · профиль `{}` · правил: {}",
        args.listen,
        profile.name,
        router.rule_count()
    );
    println!("Нажмите Ctrl+C, чтобы остановить.");

    let serving = tokio::spawn({
        let cancel = cancel.clone();
        async move { inbound.serve(cancel).await }
    });

    tokio::signal::ctrl_c()
        .await
        .context("не удалось подписаться на Ctrl+C")?;
    println!("\nОстанавливаюсь…");
    cancel.cancel();
    let _ = serving.await;

    // Закрывать соединение обязательно: без прощального пакета сервер
    // продержит сессию до истечения тайм-аута.
    let _ = outbound.close().await;

    let traffic = metrics.total();
    println!(
        "Передано {} · принято {} · соединений {}",
        penguin_core::stats::format_bytes(traffic.uploaded),
        penguin_core::stats::format_bytes(traffic.downloaded),
        traffic.connections
    );
    Ok(())
}

/// Выбирает профиль по имени или берёт активный.
pub fn pick_profile<'a>(config: &'a RootConfig, wanted: Option<&str>) -> Result<&'a Profile> {
    match wanted {
        Some(name) => config
            .profiles
            .iter()
            .find(|p| p.id.as_str() == name || p.name == name)
            .with_context(|| format!("нет профиля `{name}`")),
        None => {
            if config.profiles.is_empty() {
                bail!(
                    "в настройках нет ни одного профиля — добавьте его в {}",
                    penguin_config::paths::CONFIG_FILE
                );
            }
            config.active().context("активный профиль не найден")
        }
    }
}

/// Логин и пароль для локального прокси, если они заданы.
fn credentials_for(config: &RootConfig, kind: Kind) -> Option<Credentials> {
    let inbound = match kind {
        Kind::Socks5 => config.network.socks.as_ref(),
        Kind::Http => config.network.http.as_ref(),
    }?;
    let auth = inbound.auth.as_ref()?;
    Some(Credentials {
        username: auth.username.clone(),
        password: auth.password.clone(),
    })
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::network::{InboundAuth, InboundConfig};
    use penguin_config::schema::outbound::RawOutbound;
    use serde_json::json;

    use super::*;

    fn config_with(profiles: &[&str]) -> RootConfig {
        let mut config = RootConfig::default();
        for id in profiles {
            config.profiles.push(Profile::new(
                *id,
                *id,
                RawOutbound::new(
                    "hysteria2",
                    json!({ "server": "example.com:443", "auth": "x" }),
                ),
            ));
        }
        config
    }

    #[test]
    fn picks_the_named_profile() {
        let config = config_with(&["home", "office"]);
        assert_eq!(
            pick_profile(&config, Some("office"))
                .expect("есть")
                .id
                .as_str(),
            "office"
        );
    }

    #[test]
    fn picks_the_first_profile_when_none_is_active() {
        // Клиент с единственным профилем не должен требовать выбирать его
        // руками.
        let config = config_with(&["home"]);
        assert_eq!(
            pick_profile(&config, None).expect("есть").id.as_str(),
            "home"
        );
    }

    #[test]
    fn empty_config_explains_what_to_do() {
        let err = pick_profile(&RootConfig::default(), None).expect_err("профилей нет");
        assert!(
            err.to_string().contains("config.toml"),
            "не подсказал файл: {err}"
        );
    }

    #[test]
    fn unknown_profile_is_named_in_the_error() {
        let config = config_with(&["home"]);
        let err = pick_profile(&config, Some("нет-такого")).expect_err("нет профиля");
        assert!(err.to_string().contains("нет-такого"));
    }

    #[test]
    fn credentials_come_from_the_matching_inbound() {
        let mut config = RootConfig::default();
        config.network.socks = Some(InboundConfig {
            listen: "127.0.0.1:1080".parse().expect("адрес"),
            auth: Some(InboundAuth {
                username: "user".to_owned(),
                password: "secret".to_owned(),
            }),
        });

        assert!(credentials_for(&config, Kind::Socks5).is_some());
        // У HTTP-прокси свои настройки; чужой пароль ему не достаётся.
        assert!(credentials_for(&config, Kind::Http).is_none());
    }
}
