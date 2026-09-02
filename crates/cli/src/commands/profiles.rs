//! Профили: список и проверка настроек.
//!
//! Проверка идёт **без сети**: разбираются параметры протокола и его
//! собственные требования к ним. Ошибку в адресе или в отсутствующем пароле
//! пользователь узнаёт сразу, а не через минуту неудачного подключения.

use std::sync::Arc;

use anyhow::{Context, Result};
use penguin_config::RootConfig;
use penguin_dns::resolver::SystemResolver;
use penguin_engine::direct::SystemDialer;
use penguin_engine::outbounds::OutboundPool;
use serde::Serialize;

use crate::args::ProfilesCommand;
use crate::output::{Format, emit, table};

/// Строка списка профилей.
#[derive(Debug, Serialize)]
struct ProfileRow {
    id: String,
    name: String,
    protocol: String,
    server: String,
    active: bool,
    managed: bool,
}

/// Результат проверки одного профиля.
#[derive(Debug, Serialize)]
struct CheckRow {
    id: String,
    ok: bool,
    message: String,
}

/// Выполняет команду.
pub fn run(config: &RootConfig, command: &ProfilesCommand, format: Format) -> Result<()> {
    match command {
        ProfilesCommand::List => list(config, format),
        ProfilesCommand::Check { profile } => check(config, profile.as_deref(), format),
    }
}

fn list(config: &RootConfig, format: Format) -> Result<()> {
    let active = config.active().map(|p| p.id.clone());

    let rows: Vec<ProfileRow> = config
        .profiles
        .iter()
        .map(|profile| ProfileRow {
            id: profile.id.to_string(),
            name: profile.name.clone(),
            protocol: profile.outbound.protocol.clone(),
            // Адрес сервера показывается как есть, без разбора: интерфейсу
            // незачем знать схему параметров протокола.
            server: profile
                .outbound
                .field("server")
                .and_then(|v| v.as_str())
                .unwrap_or("—")
                .to_owned(),
            active: active.as_ref() == Some(&profile.id),
            managed: profile.is_managed(),
        })
        .collect();

    emit(format, &rows, |rows| {
        if rows.is_empty() {
            return "Профилей нет.".to_owned();
        }
        let table_rows: Vec<Vec<String>> = rows
            .iter()
            .map(|row| {
                vec![
                    if row.active {
                        "→".to_owned()
                    } else {
                        " ".to_owned()
                    },
                    row.name.clone(),
                    row.protocol.clone(),
                    row.server.clone(),
                    if row.managed {
                        "из подписки".to_owned()
                    } else {
                        String::new()
                    },
                ]
            })
            .collect();
        table(&["", "имя", "протокол", "сервер", ""], &table_rows)
    });
    Ok(())
}

fn check(config: &RootConfig, wanted: Option<&str>, format: Format) -> Result<()> {
    let pool = OutboundPool::new(Arc::new(SystemDialer::new(Arc::new(SystemResolver))));

    let profiles: Vec<_> = match wanted {
        Some(name) => vec![
            config
                .profiles
                .iter()
                .find(|p| p.id.as_str() == name || p.name == name)
                .with_context(|| format!("нет профиля `{name}`"))?,
        ],
        None => config.profiles.iter().collect(),
    };

    let rows: Vec<CheckRow> = profiles
        .iter()
        .map(|profile| match pool.validate(profile) {
            Ok(()) => CheckRow {
                id: profile.id.to_string(),
                ok: true,
                message: "настройки верны".to_owned(),
            },
            Err(err) => CheckRow {
                id: profile.id.to_string(),
                ok: false,
                message: err.to_string(),
            },
        })
        .collect();

    emit(format, &rows, |rows| {
        if rows.is_empty() {
            return "Профилей нет.".to_owned();
        }
        let table_rows: Vec<Vec<String>> = rows
            .iter()
            .map(|row| {
                vec![
                    if row.ok {
                        "✓".to_owned()
                    } else {
                        "✗".to_owned()
                    },
                    row.id.clone(),
                    row.message.clone(),
                ]
            })
            .collect();
        table(&["", "профиль", "результат"], &table_rows)
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::outbound::RawOutbound;
    use penguin_config::schema::profile::Profile;
    use serde_json::json;

    use super::*;

    fn config() -> RootConfig {
        let mut config = RootConfig::default();
        config.profiles.push(Profile::new(
            "home",
            "Домашний",
            RawOutbound::new(
                "hysteria2",
                json!({ "server": "example.com:443", "auth": "x" }),
            ),
        ));
        config.profiles.push(Profile::new(
            "broken",
            "Сломанный",
            RawOutbound::new("hysteria2", json!({ "server": "example.com:443" })),
        ));
        config
    }

    #[test]
    fn listing_marks_the_active_profile() {
        let config = config();
        let active = config.active().expect("есть активный");
        // Явно выбранного нет — активным считается первый.
        assert_eq!(active.id.as_str(), "home");
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn check_separates_good_from_broken() {
        // Проверка идёт без сети: ошибку в поле надо показать сразу.
        let pool = OutboundPool::new(Arc::new(SystemDialer::new(Arc::new(SystemResolver))));
        let config = config();

        assert!(pool.validate(&config.profiles[0]).is_ok());
        assert!(
            pool.validate(&config.profiles[1]).is_err(),
            "профиль без пароля прошёл проверку"
        );
    }

    #[test]
    fn unknown_profile_is_reported() {
        let config = config();
        let err = check(&config, Some("нет-такого"), Format::Text).expect_err("нет профиля");
        assert!(err.to_string().contains("нет-такого"));
    }
}
