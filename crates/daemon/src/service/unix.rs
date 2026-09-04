//! Демонизация и сигналы.
//!
//! Демонизировать себя не нужно и вредно: служба должна оставаться на переднем
//! плане, а поднимать и останавливать её — дело systemd и launchd. От нас
//! требуется разобрать `SIGTERM` (это делает [`crate::runtime`]) и не потерять
//! журнал.
//!
//! # Куда пишется журнал
//!
//! В файл, а не в стандартный поток. У systemd поток ещё подхватывает journald,
//! а launchd без `StandardErrorPath` выбрасывает его целиком — и служба,
//! которая не поднялась, не оставляет после себя ни строчки. Файл один и тот
//! же на всех системах (на Windows его открывает [`super::windows`]), и искать
//! его человеку приходится в одном месте.

use std::path::PathBuf;

use anyhow::Result;

/// Запускает демона под управлением systemd или launchd.
pub fn run(config_dir: Option<PathBuf>) -> Result<()> {
    // Журнал до всего остального: ошибка сборки настроек — как раз то, ради
    // чего его и заводят.
    let _guard = crate::runtime::open_store(config_dir.clone())
        .ok()
        .and_then(|store| crate::logging::init_file(store.paths().data_dir(), false));

    crate::runtime::run_blocking(config_dir)
}
