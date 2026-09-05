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
    // Ссылки разворачиваем: описание службы хранит путь как есть, и ссылка в
    // нём переживает только до тех пор, пока указывает туда же. Поставка
    // кладёт рядом с программой ссылку на неё (`scripts/package.sh`), и
    // зарегистрированная служба ломалась бы при каждой пересборке.
    let executable = executable.canonicalize().unwrap_or(executable);

    penguin_platform::service::install(&executable).context("не удалось поставить службу")?;

    println!("Служба установлена. Запустить: penguin service start");
    Ok(())
}

/// Отвечает ли служба на запросы.
///
/// Не то же самое, что «числится работающей». Демон, зависший с поднятым
/// тоннелем, для диспетчера служб жив: процесс есть, состояние `running`. А на
/// запросы он не отвечает, и толку от него ровно столько же, сколько от
/// остановленного, — с той разницей, что маршруты машины идут через него.
///
/// Своя среда выполнения: спрашивают отсюда из обычного, не асинхронного кода —
/// из команды `service ensure`, которая идёт отдельным процессом с правами.
pub fn responds() -> bool {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    runtime.block_on(penguin_ipc::client::answers_service())
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
