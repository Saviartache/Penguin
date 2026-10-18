//! Подписка Amnezia: забрать серверы у шлюза и завести управляемыми профилями.
//!
//! Сеть к шлюзу — отдельный внешний сервис, в терминале, не в окне (`AGENTS.md`
//! §1.7). Устройство подписки (ключи и `installation_uuid`) переиспользуется:
//! новый ключ на каждый запрос тратил бы слот Amnezia. Хранится оно в каталоге
//! данных **пользователя**, а не в общем: окно запускает эту команду от имени
//! пользователя, и в общий каталог службы (его создаёт root) ему не писать.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use penguin_config::schema::profile::Profile;
use penguin_config::{ConfigStore, Paths, RootConfig};
use penguin_subscription::{Device, Options, SubscriptionKey};
use serde::{Deserialize, Serialize};

use crate::args::SubscriptionCommand;
use crate::output::{Format, emit, ok, table};

/// Имя файла-спутника с устройствами подписок.
const STORE_FILE: &str = "subscriptions.json";

/// Заведённая подписка: устройство и ключ, чтобы обновляться без повторной вставки.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    device: Device,
    key: String,
}

/// Файл-спутник: подписки по идентификатору.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    subscriptions: BTreeMap<String, Entry>,
}

/// Строка списка подписок/заведённых профилей.
#[derive(Debug, Serialize)]
struct Row {
    subscription: String,
    profile: String,
    name: String,
}

/// Выполняет команду.
///
/// Настройки открываются лениво — только когда команда их пишет или читает:
/// обновление в JSON (путь окна) к ним не прикасается, поэтому не упирается в
/// общий каталог службы, недоступный пользователю.
pub fn run(
    command: &SubscriptionCommand,
    config_dir: Option<&std::path::Path>,
    format: Format,
) -> Result<()> {
    match command {
        SubscriptionCommand::Refresh {
            key,
            id,
            connect_event,
            dev,
            endpoint,
            country,
        } => {
            let options = Options {
                connect_event: *connect_event,
                gateway_public_key: if *dev {
                    penguin_subscription::GATEWAY_PUBLIC_KEY_DEV
                } else {
                    penguin_subscription::GATEWAY_PUBLIC_KEY_PROD
                },
                endpoint: endpoint
                    .as_deref()
                    .unwrap_or(penguin_subscription::GATEWAY_ENDPOINT),
                country: country.as_deref(),
            };
            refresh(config_dir, key.as_deref(), id.as_deref(), &options, format)
        }
        SubscriptionCommand::List => list(config_dir, format),
        SubscriptionCommand::Remove { id } => remove(config_dir, id, format),
    }
}

/// Открывает настройки: указанный каталог либо общий.
fn open_store(config_dir: Option<&std::path::Path>) -> Result<ConfigStore> {
    match config_dir {
        Some(dir) => Ok(ConfigStore::new(Paths::rooted(dir))),
        None => ConfigStore::discover().context("каталог настроек"),
    }
}

/// Путь файла-спутника в каталоге данных пользователя.
fn store_path() -> Result<PathBuf> {
    let paths = Paths::user().context("каталог данных пользователя неизвестен")?;
    Ok(paths.data_dir().join(STORE_FILE))
}

/// Читает файл-спутник; нет файла — пустой набор.
fn load_devices() -> Result<Store> {
    let path = store_path()?;
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("не разобрать {}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
        Err(err) => Err(err).with_context(|| format!("не прочитать {}", path.display())),
    }
}

/// Пишет файл-спутник (создаёт каталог при нужде).
fn save_devices(devices: &Store) -> Result<()> {
    let path = store_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("каталог {}", dir.display()))?;
    }
    let json = serde_json::to_vec_pretty(devices).context("сборка JSON подписок")?;
    std::fs::write(&path, json).with_context(|| format!("не записать {}", path.display()))
}

fn refresh(
    config_dir: Option<&std::path::Path>,
    key: Option<&str>,
    only: Option<&str>,
    options: &Options<'_>,
    format: Format,
) -> Result<()> {
    let mut devices = load_devices()?;

    // Что обновлять: новый ключ, одна заведённая по `--id`, либо все заведённые.
    let targets: Vec<(String, String)> = match key {
        Some(raw) => {
            let parsed = SubscriptionKey::parse(raw).context("ключ подписки")?;
            let id = parsed.id().to_owned();
            match devices.subscriptions.get_mut(&id) {
                Some(entry) => entry.key = raw.to_owned(),
                None => {
                    let device = Device::generate().context("генерация устройства")?;
                    devices.subscriptions.insert(
                        id.clone(),
                        Entry {
                            device,
                            key: raw.to_owned(),
                        },
                    );
                }
            }
            vec![(id, raw.to_owned())]
        }
        None => {
            let wanted: Vec<(String, String)> = devices
                .subscriptions
                .iter()
                .filter(|(id, _)| only.is_none_or(|want| want == id.as_str()))
                .map(|(id, entry)| (id.clone(), entry.key.clone()))
                .collect();
            if wanted.is_empty() {
                match only {
                    Some(id) => bail!("подписки `{id}` нет"),
                    None => bail!("нет заведённых подписок — укажите ключ `vpn://…`"),
                }
            }
            wanted
        }
    };

    let mut added = Vec::new();

    for (id, raw_key) in targets {
        let parsed = SubscriptionKey::parse(&raw_key).context("ключ подписки")?;
        let device = &devices.subscriptions[&id].device;
        let profiles = penguin_subscription::refresh(&parsed, device, options)
            .with_context(|| format!("обновление подписки {id}"))?;
        added.extend(profiles);
    }

    // Устройство — всегда (слоты), иначе следующий запрос заведёт новое.
    save_devices(&devices)?;

    // Текстовый путь (пользователь терминала) пишет настройки сам; в JSON
    // профили забирает окно и сохраняет через демона — файл не трогаем, чтобы
    // не писать его дважды.
    if format == Format::Text {
        let store = open_store(config_dir)?;
        let mut config = store.load().context("чтение настроек")?;
        merge(&mut config, &added);
        store.save(&config).context("запись настроек")?;
    }

    emit(format, &added, |profiles| render_added(profiles));
    Ok(())
}

/// Переносит свежие профили в настройки, заменяя управляемые той же подпиской.
fn merge(config: &mut RootConfig, added: &[Profile]) {
    let mut ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for profile in added {
        if let Some(id) = &profile.subscription {
            ids.insert(id.clone());
        }
    }
    for id in &ids {
        drop_managed(config, id);
    }
    config.profiles.extend_from_slice(added);
}

/// Таблица заведённых профилей либо строка «пусто».
fn render_added(profiles: &[Profile]) -> String {
    if profiles.is_empty() {
        return "Серверов не пришло.".to_owned();
    }
    let rows: Vec<Vec<String>> = profiles
        .iter()
        .map(|profile| {
            vec![
                profile.subscription.clone().unwrap_or_default(),
                profile.id.to_string(),
                profile.name.clone(),
            ]
        })
        .collect();
    table(&["подписка", "профиль", "имя"], &rows)
}

fn list(config_dir: Option<&std::path::Path>, format: Format) -> Result<()> {
    let devices = load_devices()?;
    let config = open_store(config_dir)?.load().context("чтение настроек")?;

    let rows: Vec<Row> = devices
        .subscriptions
        .keys()
        .flat_map(|id| {
            config
                .profiles
                .iter()
                .filter(move |profile| profile.subscription.as_deref() == Some(id))
                .map(move |profile| Row {
                    subscription: id.clone(),
                    profile: profile.id.to_string(),
                    name: profile.name.clone(),
                })
        })
        .collect();

    emit(format, &rows, |rows| render_rows(rows, "Подписок нет"));
    Ok(())
}

fn remove(config_dir: Option<&std::path::Path>, id: &str, format: Format) -> Result<()> {
    let mut devices = load_devices()?;
    let had_device = devices.subscriptions.remove(id).is_some();

    let store = open_store(config_dir)?;
    let mut config = store.load().context("чтение настроек")?;
    let before = config.profiles.len();
    drop_managed(&mut config, id);
    let removed = before - config.profiles.len();

    if !had_device && removed == 0 {
        bail!("подписки `{id}` нет");
    }

    store.save(&config).context("запись настроек")?;
    save_devices(&devices)?;

    emit(format, &removed, |count| {
        ok(format!("Убрана подписка {id}: профилей удалено {count}"))
    });
    Ok(())
}

/// Убирает профили подписки; активный на удалённом — снимается.
fn drop_managed(config: &mut RootConfig, id: &str) {
    config
        .profiles
        .retain(|profile| profile.subscription.as_deref() != Some(id));
    if config
        .active_profile
        .as_ref()
        .is_some_and(|active| config.profile(active).is_none())
    {
        config.active_profile = None;
    }
}

fn render_rows(rows: &[Row], empty: &str) -> String {
    if rows.is_empty() {
        return empty.to_owned();
    }
    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                row.subscription.clone(),
                row.profile.clone(),
                row.name.clone(),
            ]
        })
        .collect();
    table(&["подписка", "профиль", "имя"], &table_rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use penguin_config::schema::outbound::RawOutbound;
    use serde_json::json;

    fn managed(id: &str, sub: &str) -> Profile {
        let mut profile = Profile::new(id, id, RawOutbound::new("wireguard", json!({})));
        profile.subscription = Some(sub.to_owned());
        profile
    }

    #[test]
    fn refresh_replaces_only_its_own_profiles() {
        let mut config = RootConfig::default();
        config.profiles.push(managed("a-nl", "amnezia-1"));
        config.profiles.push(managed("a-de", "amnezia-1"));
        config.profiles.push(managed("b-nl", "amnezia-2"));
        config.profiles.push(Profile::new(
            "home",
            "home",
            RawOutbound::new("hysteria2", json!({})),
        ));

        merge(&mut config, &[managed("a-us", "amnezia-1")]);

        let ids: Vec<&str> = config.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["b-nl", "home", "a-us"]);
    }

    #[test]
    fn removing_a_subscription_clears_a_dangling_active_choice() {
        let mut config = RootConfig::default();
        config.profiles.push(managed("a-nl", "amnezia-1"));
        config.active_profile = Some(penguin_core::id::ProfileId::new("a-nl"));

        drop_managed(&mut config, "amnezia-1");

        assert!(config.profiles.is_empty());
        assert!(config.active_profile.is_none());
    }

    #[test]
    fn removing_a_subscription_keeps_an_unrelated_active_choice() {
        let mut config = RootConfig::default();
        config.profiles.push(managed("a-nl", "amnezia-1"));
        config.profiles.push(Profile::new(
            "home",
            "home",
            RawOutbound::new("hysteria2", json!({})),
        ));
        config.active_profile = Some(penguin_core::id::ProfileId::new("home"));

        drop_managed(&mut config, "amnezia-1");

        assert_eq!(
            config.active_profile.as_ref().map(|p| p.as_str()),
            Some("home")
        );
    }

    #[test]
    fn a_store_round_trips_through_json() {
        let mut store = Store::default();
        store.subscriptions.insert(
            "amnezia-1".to_owned(),
            Entry {
                device: Device::generate().expect("устройство"),
                key: "vpn://x".to_owned(),
            },
        );
        let json = serde_json::to_vec(&store).expect("json");
        let back: Store = serde_json::from_slice(&json).expect("разбор");
        assert!(back.subscriptions.contains_key("amnezia-1"));
    }
}
