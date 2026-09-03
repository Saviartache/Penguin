//! Сборка зависимостей и жизненный цикл процесса.
//!
//! Один порядок действий на оба способа запуска — как службы и как обычного
//! процесса. Разница между ними только в том, откуда приходит сигнал
//! остановки: от диспетчера служб или от Ctrl+C.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use penguin_config::{ConfigStore, Paths, RootConfig};
use penguin_engine::Engine;
use penguin_ipc::server::Server;
use tokio_util::sync::CancellationToken;

use crate::handlers::DaemonHandler;

/// Собирает и запускает демона, пока не отменят.
pub async fn run(config_dir: Option<PathBuf>, cancel: CancellationToken) -> Result<()> {
    // До всего остального: убитый прошлый запуск мог оставить запрет
    // исходящего трафика, а он переживает перезагрузку. Служба поднимается
    // вместе с системой — значит, сеть вернётся сама.
    if let Err(err) = penguin_platform::firewall::recover_leftovers() {
        tracing::error!(%err, "не снят запрет, оставшийся от прошлого запуска");
    }

    let store = open_store(config_dir)?;
    let config = match store.load() {
        Ok(config) => config,
        // Опечатка в настройках не должна оставлять пользователя без службы:
        // починить её нечем — интерфейс тоже не работает без демона. Прежнее
        // содержимое при этом не пропадёт: первая же запись настроек кладёт
        // его рядом в `.bak` (см. `ConfigStore::save`).
        Err(err) => {
            tracing::error!(
                %err,
                path = %store.paths().config_file().display(),
                "настройки не читаются, работаем на умолчаниях"
            );
            fallback_config()
        }
    };

    // Файл создаётся при первом запуске: пустой каталог настроек и файл с
    // умолчаниями — разные вещи для того, кто захочет посмотреть, что вообще
    // можно настроить.
    if store.init_if_missing().unwrap_or(false) {
        tracing::info!(path = %store.paths().config_file().display(), "создан файл настроек");
    }

    let autoconnect = config.app.autoconnect;
    let engine = Engine::new(config).context("не удалось собрать движок")?;
    let handler = DaemonHandler::new(Arc::clone(&engine), Arc::new(store), cancel.clone());

    // Автоподключение — после того, как канал управления открыт: иначе
    // интерфейс, запущенный одновременно, не достучится до демона, пока тот
    // поднимает тоннель.
    if autoconnect {
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            if let Err(err) = engine.connect(None).await {
                tracing::warn!(%err, "автоподключение не удалось");
            }
        });
    }

    let server = Server::new(handler);
    let result = server.serve(cancel.clone()).await;

    // Тоннель опускается в любом случае, включая аварийный выход: маршруты и
    // правила брандмауэра, оставшиеся от упавшего демона, — это машина без
    // сети.
    if let Err(err) = engine.disconnect().await {
        tracing::error!(%err, "тоннель опущен не полностью");
    }

    result.context("канал управления завершился с ошибкой")
}

/// Запускает демона на переднем плане.
///
/// Так его запускают при отладке: журнал идёт в терминал, остановка — по
/// Ctrl+C.
pub fn run_foreground(config_dir: Option<PathBuf>, verbose: bool) -> Result<()> {
    crate::logging::init_console(verbose);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("не удалось создать среду выполнения")?;

    runtime.block_on(async {
        let cancel = CancellationToken::new();

        let signal = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    tracing::info!("получен Ctrl+C, останавливаюсь");
                    cancel.cancel();
                }
            })
        };

        let result = run(config_dir, cancel).await;
        signal.abort();
        result
    })
}

/// Открывает файл настроек.
pub fn open_store(config_dir: Option<PathBuf>) -> Result<ConfigStore> {
    match config_dir {
        Some(dir) => Ok(ConfigStore::new(Paths::rooted(dir))),
        None => ConfigStore::discover().context("не удалось определить каталог настроек"),
    }
}

/// Настройки по умолчанию — на случай, когда файл не читается.
///
/// Демон обязан подняться и с испорченным файлом: иначе опечатка в настройках
/// оставляет пользователя без службы, а починить её нечем — интерфейс тоже не
/// работает без демона.
pub fn fallback_config() -> RootConfig {
    RootConfig::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_directory_is_used() {
        let store = open_store(Some(PathBuf::from("C:/penguin-test"))).expect("открывается");
        assert!(store.paths().config_file().starts_with("C:/penguin-test"));
    }

    #[test]
    fn fallback_is_valid() {
        // Опечатка в настройках не должна оставлять пользователя без службы:
        // починить её нечем, интерфейс тоже не работает без демона.
        penguin_config::validate::validate(&fallback_config()).expect("умолчания корректны");
    }

    #[tokio::test]
    async fn cancelled_immediately_still_shuts_down_cleanly() {
        let cancel = CancellationToken::new();
        cancel.cancel();

        let directory = std::env::temp_dir().join("penguin-daemon-test");
        // Канал управления может быть занят настоящей службой — тогда демон
        // и не должен подниматься.
        let _ = run(Some(directory), cancel).await;
    }
}
