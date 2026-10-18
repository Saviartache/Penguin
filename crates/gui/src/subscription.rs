//! Обновление подписки Amnezia: окно просит об этом себя-как-CLI.
//!
//! Сеть к шлюзу идёт мимо окна (`AGENTS.md` §1.7): `penguin subscription
//! refresh <ключ> --json` делает запрос и печатает профили, а окно их
//! вливает в настройки через демона.

use penguin_config::schema::profile::Profile;

/// Обновляет подписку по ключу `vpn://…` (окно выбора серверов).
pub(crate) async fn refresh(key: String) -> Result<Vec<Profile>, String> {
    run(vec![
        "subscription".to_owned(),
        "refresh".to_owned(),
        key,
        "--json".to_owned(),
    ])
    .await
}

/// Обновляет локацию активного профиля перед подключением (событие подключения).
///
/// `country` — страна активного сервера: обновляется только она, а не все 50+
/// локаций подписки.
pub(crate) async fn refresh_subscription(
    id: String,
    country: Option<String>,
) -> Result<Vec<Profile>, String> {
    let mut args = vec![
        "subscription".to_owned(),
        "refresh".to_owned(),
        "--id".to_owned(),
        id,
        "--connect-event".to_owned(),
        "--json".to_owned(),
    ];
    if let Some(country) = country.filter(|code| !code.is_empty()) {
        args.push("--country".to_owned());
        args.push(country);
    }
    run(args).await
}

/// Запускает `penguin subscription …` и разбирает присланные профили.
async fn run(args: Vec<String>) -> Result<Vec<Profile>, String> {
    tokio::task::spawn_blocking(move || {
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = crate::self_exec::run_self(&borrowed)?;
        serde_json::from_slice::<Vec<Profile>>(&output)
            .map_err(|err| format!("ответ подписки не разобран: {err}"))
    })
    .await
    .map_err(|err| err.to_string())?
}
