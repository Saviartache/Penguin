//! Служба: держит тоннель и обслуживает канал управления.
//!
//! Привилегированные действия (TUN, маршруты, брандмауэр) делает она; окно
//! просит через канал управления. Библиотека: исполняемый файл — `crates/app`.

pub mod handlers;
pub mod instance;
pub mod logging;
mod preparation;
mod readiness;
pub mod runtime;
pub mod service;

use anyhow::{Context, Result};

pub use penguin_ipc::current_user_id;
pub use preparation::prepare_service;
pub use readiness::wait_until_ready;

/// Ставит службу и заводит общий каталог настроек.
pub fn install() -> Result<()> {
    prepare_service(None, None)?;
    let executable = std::env::current_exe().context("не удалось узнать свой путь")?;
    // Служба хранит путь как есть; ссылка из поставки ломалась бы при пересборке
    let executable = executable.canonicalize().unwrap_or(executable);

    penguin_platform::service::install(&executable).context("не удалось поставить службу")?;

    println!("Служба установлена. Запустить: penguin service start");
    Ok(())
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
