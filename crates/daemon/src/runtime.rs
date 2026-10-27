//! Сборка зависимостей и жизненный цикл процесса.
//!
//! Один порядок для запуска службой и обычным процессом; отличается источник
//! сигнала остановки.

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
    run_with_paths(config_dir.map(Paths::rooted), cancel).await
}

async fn run_with_paths(paths: Option<Paths>, cancel: CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Ok(());
    }
    let result = run_inner(paths, cancel).await;
    if let Err(err) = &result {
        tracing::error!(error = %format_args!("{err:#}"), "daemon startup or runtime failed");
    }
    result
}

async fn run_inner(paths: Option<Paths>, cancel: CancellationToken) -> Result<()> {
    // Раньше сокета: второй демон не должен убрать сокет первого. Объявлена первой — отпускается последней.
    let _single = tokio::task::spawn_blocking(crate::instance::lock_daemon)
        .await
        .context("ожидание блокировки прервано")??;
    // Единственность занимаем до записи настроек и восстановления сети
    let listener = penguin_ipc::transport::listen().context("could not bind control transport")?;
    let paths = paths
        .map_or_else(Paths::discover, Ok)
        .context("could not determine configuration paths")?;
    let store = ConfigStore::new(paths);
    let config = match store.load() {
        Ok(config) => config,
        // Без демона интерфейс не починит настройки; старый файл уйдёт в `.bak`
        Err(_) => {
            // Ошибка разбора может цитировать секреты
            tracing::error!(
                path = %store.paths().config_file().display(),
                "настройки не читаются, работаем на умолчаниях"
            );
            fallback_config()
        }
    };

    crate::logging::set_level(config.app.log_level);

    // Файл с умолчаниями виден пользователю как образец
    if store.init_if_missing().unwrap_or(false) {
        tracing::info!(path = %store.paths().config_file().display(), "создан файл настроек");
    }

    // Убрать следы убитого запуска (запрет трафика, адаптер, DNS) до движка;
    // свой адаптер узнаём по адресу из настроек
    penguin_platform::leftovers::recover(config.network.tun.ipv4);

    let engine = Engine::new(config).context("не удалось собрать движок")?;
    // Без базы правила по странам молчат, пока окно её не пришлёт
    let geoip = store.paths().geoip_file();
    if geoip.exists()
        && let Err(err) = engine.load_geoip(&geoip)
    {
        tracing::warn!(%err, "база GeoIP не загружена");
    }
    let handler = DaemonHandler::new(Arc::clone(&engine), Arc::new(store), cancel.clone());

    // Автоподключение — забота клиента: служба стоит на автозапуске, и, поднимая
    // тоннель сама, она делала бы это при загрузке системы, до запуска программы.

    let server = Server::new(handler);
    let result = server.serve_with_listener(listener, cancel.clone()).await;
    cancel.cancel();

    // Всегда: остатки маршрутов и правил оставляют машину без сети
    if let Err(err) = engine.disconnect().await {
        tracing::error!(%err, "тоннель опущен не полностью");
    }

    result.context("канал управления завершился с ошибкой")
}

/// Запускает демона на переднем плане.
///
/// Журнал идёт в терминал, остановка по Ctrl+C.
pub fn run_foreground(config_dir: Option<PathBuf>, verbose: bool) -> Result<()> {
    crate::logging::init_console(verbose);
    run_blocking(config_dir)
}

/// Крутит демона до сигнала остановки. Журнал настраивает вызывающий.
pub fn run_blocking(config_dir: Option<PathBuf>) -> Result<()> {
    run_blocking_paths(config_dir.map(Paths::rooted))
}

pub(crate) fn run_blocking_paths(paths: Option<Paths>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("не удалось создать среду выполнения")?;

    runtime.block_on(async {
        let cancel = CancellationToken::new();

        let signal = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                if wait_for_stop().await {
                    tracing::info!("получен сигнал остановки");
                    cancel.cancel();
                }
            })
        };

        let result = run_with_paths(paths, cancel).await;
        signal.abort();
        result
    })
}

/// Ждёт Ctrl+C или `SIGTERM` (останов службой). `false` — сигналы не разобрать.
#[cfg(unix)]
async fn wait_for_stop() -> bool {
    use tokio::signal::unix::{SignalKind, signal};

    let Ok(mut terminate) = signal(SignalKind::terminate()) else {
        return tokio::signal::ctrl_c().await.is_ok();
    };

    tokio::select! {
        Ok(()) = tokio::signal::ctrl_c() => true,
        Some(()) = terminate.recv() => true,
        else => false,
    }
}

/// Ждёт Ctrl+C; службу Windows останавливает диспетчер.
#[cfg(not(unix))]
async fn wait_for_stop() -> bool {
    tokio::signal::ctrl_c().await.is_ok()
}

/// Открывает файл настроек.
pub fn open_store(config_dir: Option<PathBuf>) -> Result<ConfigStore> {
    match config_dir {
        Some(dir) => Ok(ConfigStore::new(Paths::rooted(dir))),
        None => ConfigStore::discover().context("не удалось определить каталог настроек"),
    }
}

/// Умолчания на случай нечитаемого файла: демон обязан подняться.
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
        penguin_config::validate::validate(&fallback_config()).expect("умолчания корректны");
    }

    #[tokio::test]
    async fn cancelled_immediately_still_shuts_down_cleanly() {
        let cancel = CancellationToken::new();
        cancel.cancel();

        let temp = tempfile::tempdir().expect("temporary directory");
        let directory = temp.path().join("must-not-be-created");
        run(Some(directory.clone()), cancel)
            .await
            .expect("cancelled startup is a no-op");
        assert!(!directory.exists());
        let cancel = CancellationToken::new();
        cancel.cancel();
        run(None, cancel)
            .await
            .expect("no discovery or IPC on cancellation");
    }
}
