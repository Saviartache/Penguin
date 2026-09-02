//! Служба: держит тоннель и обслуживает канал управления.
//!
//! Работает под системной учётной записью. Всё, что требует прав — TUN,
//! маршруты, брандмауэр, — делает она; окно только просит через канал
//! управления.
//!
//! Библиотека, а не программа: в поставке один исполняемый файл, и кем ему
//! быть, решает он сам по своим аргументам (`crates/app`). Здесь — только то,
//! что делает служба.

pub mod args;
pub mod handlers;
pub mod logging;
pub mod runtime;
pub mod service;

use std::path::PathBuf;

use anyhow::{Context, Result};
use penguin_config::Paths;

/// Ставит службу и заводит общий каталог настроек.
pub fn install() -> Result<()> {
    let executable = std::env::current_exe().context("не удалось узнать свой путь")?;
    penguin_platform::service::install(&executable).context("не удалось поставить службу")?;

    // Общий каталог настроек заводится здесь и только здесь: прав на него нет
    // ни у окна, ни у службы в работе, а нужен он им обоим. Без него служба
    // читала бы файл из профиля `LocalSystem`, а окно правило бы файл в
    // профиле пользователя — два разных файла, и правки молча не действуют.
    match prepare_shared_config() {
        Ok(Some(path)) => println!("Настройки: {}", path.display()),
        Ok(None) => {}
        // Не повод отменять установку: служба поднимется и на своих
        // умолчаниях, а сказать об этом надо вслух.
        Err(err) => eprintln!("общий каталог настроек не создан: {err}"),
    }

    println!("Служба установлена. Запустить: penguin service start");
    Ok(())
}

/// Заводит общий каталог настроек и переносит туда то, что пользователь уже
/// настроил.
///
/// Возвращает путь к файлу настроек или `None`, если система не сказала, где
/// общий каталог.
fn prepare_shared_config() -> Result<Option<PathBuf>> {
    let Some(machine) = Paths::machine() else {
        return Ok(None);
    };
    machine.ensure_dirs().context("не создаются каталоги")?;

    let target = machine.config_file();
    if target.exists() {
        return Ok(Some(target));
    }

    // Пользователь мог настроить клиента до установки службы — в прокси-режиме
    // это законный и рекомендованный порядок. Заставлять его настраивать всё
    // заново только потому, что файл переехал, незачем.
    if let Ok(user) = Paths::user()
        && user.config_file().exists()
    {
        std::fs::copy(user.config_file(), &target).context("не переносятся настройки")?;
        println!("Настройки перенесены из {}", user.config_file().display());
    }

    Ok(Some(target))
}

/// Убирает службу.
pub fn uninstall() -> Result<()> {
    penguin_platform::service::uninstall().context("не удалось удалить службу")?;
    println!("Служба удалена.");
    Ok(())
}

/// Показывает состояние службы и заодно диагностику.
pub fn status() -> Result<()> {
    let status = penguin_platform::service::status().context("не удалось узнать состояние")?;
    println!("Служба: {}", status.as_str());

    // Диагностика печатается заодно: тот, кто спрашивает про службу, обычно
    // разбирается, почему что-то не работает.
    let diagnostics = handlers::diagnostics::collect();
    println!(
        "Права: {}",
        if diagnostics.elevated {
            "повышенные"
        } else {
            "обычные"
        }
    );
    if let Some(address) = diagnostics.default_address {
        println!("Выход наружу: {address}");
    }
    Ok(())
}
