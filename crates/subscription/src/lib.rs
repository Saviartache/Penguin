//! Клиент шлюза подписки Amnezia.
//!
//! По ключу `vpn://…` платной подписки забирает у шлюза конфиги серверов и
//! переводит их в профили Penguin (протокол `wireguard` с блоком `amnezia`).
//! Ключ подписки принадлежит пользователю — обращение легитимно.
//!
//! Шлюз — внешний сервис, отличный от обновлений (`AGENTS.md` §1.7: на GitHub
//! ходит только `update`). Поэтому это отдельный крейт, зависящий лишь от
//! `core` и `config`; сеть живёт за фичей `net` (окну она не нужна).
//!
//! Конверт и боевой ключ ([`GATEWAY_PUBLIC_KEY_PROD`]) проверены живым запросом:
//! шлюз расшифровывает запрос и отвечает по делу (`403` на чужой ключ API,
//! `501` на старую версию). Перевод ответа в профиль на живом конфиге **не
//! проверен** — нужен действующий ключ подписки.

pub mod device;
pub mod envelope;
pub mod error;
pub mod key;
pub mod translate;

#[cfg(feature = "net")]
mod gateway;

pub use device::Device;
pub use error::{SubscriptionError, SubscriptionResult};
pub use key::SubscriptionKey;

/// Куда и каким ключом шлюза обращаться.
#[derive(Debug, Clone, Copy)]
pub struct Options<'a> {
    /// PKIX-PEM открытого ключа шлюза.
    pub gateway_public_key: &'a str,
    /// Адрес шлюза (оканчивается на `/`).
    pub endpoint: &'a str,
    /// Событие подключения (`is_connect_event`): шлюз держит пир устройства,
    /// иначе давно не виденное отбраковывается, и конфиг протухает.
    pub connect_event: bool,
    /// Обновить только эту страну (reload-on-connect по активному профилю);
    /// `None` — завести все локации подписки.
    pub country: Option<&'a str>,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Self {
            gateway_public_key: GATEWAY_PUBLIC_KEY_PROD,
            endpoint: GATEWAY_ENDPOINT,
            connect_event: false,
            country: None,
        }
    }
}

/// Боевой шлюз подписки.
pub const GATEWAY_ENDPOINT: &str = "http://gw.amnezia.org:80/";

/// Версия клиента для шлюза (`app_version`).
///
/// Шлюз отклоняет слишком старые: ниже ~5.0.0 — `501 client version update is
/// required`. Взято из установленного AmneziaVPN 5.0.3; слать свою версию
/// (0.7.x) нельзя. Поднять, если шлюз начнёт требовать новее.
pub const GATEWAY_CLIENT_VERSION: &str = "5.0.3";

/// Боевой ключ шлюза, извлечённый из AmneziaVPN.app 5.0.3 (`PROD_AGW_PUBLIC_KEY`).
///
/// Подтверждён живым запросом: именно им шлюз расшифровывает конверт (второй,
/// `DEV`, даёт `500`).
pub const GATEWAY_PUBLIC_KEY_PROD: &str = include_str!("keys/prod.pem");

/// Ключ dev-шлюза (`DEV_AGW_PUBLIC_KEY`); для `gw.dev.amzsvc.com`.
pub const GATEWAY_PUBLIC_KEY_DEV: &str = include_str!("keys/dev.pem");

/// Забирает у шлюза серверы подписки и переводит их в управляемые профили.
///
/// `options.country` задан — один профиль этой страны (reload-on-connect по
/// активному серверу). Иначе — все локации: первый запрос (за сервером по
/// умолчанию) заодно приносит `available_countries`, и по одному запросу
/// `v1/config` на каждую оставшуюся страну. Пара ключей и `installation_uuid`
/// из `device` переиспользуются (слоты устройств, `max_device_count`).
///
/// Ошибка отдельной страны не рушит всё: такая локация пропускается. Пустой
/// результат — ошибка (первый запрос обязан пройти).
#[cfg(feature = "net")]
pub fn refresh(
    key: &SubscriptionKey,
    device: &Device,
    options: &Options<'_>,
) -> SubscriptionResult<Vec<penguin_config::schema::profile::Profile>> {
    // Одна страна — только она (обновление активного перед подключением).
    if let Some(country) = options.country {
        let payload = key.config_payload(device, Some(country), options.connect_event);
        let body = gateway::post_config(options, &payload)?;
        return Ok(vec![translate::profile(&body, key, device, Some(country))?]);
    }

    // Все локации: первый запрос даёт сервер по умолчанию и список стран.
    let first_payload = key.config_payload(device, None, options.connect_event);
    let first_body = gateway::post_config(options, &first_payload)?;
    let default_country = translate::server_country(&first_body)?;
    let countries = translate::available_countries(&first_body)?;

    let mut profiles = vec![translate::profile(&first_body, key, device, None)?];
    for country in countries {
        if Some(&country) == default_country.as_ref() {
            continue; // уже есть из первого запроса
        }
        let payload = key.config_payload(device, Some(&country), options.connect_event);
        match gateway::post_config(options, &payload)
            .and_then(|body| translate::profile(&body, key, device, Some(&country)))
        {
            Ok(profile) => profiles.push(profile),
            Err(err) => tracing::warn!(%country, %err, "локация подписки пропущена"),
        }
    }
    Ok(profiles)
}
