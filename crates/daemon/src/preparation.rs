//! Подготовка с повышенными правами до регистрации и запуска службы.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use penguin_config::{ConfigStore, Paths, migrate, validate};

#[cfg(unix)]
#[path = "preparation_unix.rs"]
mod unix;

const MAX_CONFIG_SIZE: u64 = 4 * 1024 * 1024;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Готовит машинные каталоги и импортирует настройки; нужны права. Имеющиеся
/// настройки не заменяются. Возвращает `true`, если сменился доступ контроллера
/// (нужен перезапуск слушателя).
pub fn prepare_service(controller_uid: Option<u32>, import_config: Option<&Path>) -> Result<bool> {
    ensure!(
        penguin_platform::privilege::is_elevated(),
        "service preparation requires elevated privileges"
    );
    let machine = Paths::machine().context("machine configuration directory is unavailable")?;
    #[cfg(windows)]
    let fallback = Paths::user()
        .ok()
        .map(|paths| paths.config_file())
        .filter(|path| path.exists());
    #[cfg(windows)]
    let import_config = import_config.or(fallback.as_deref());

    prepare_config(&machine, controller_uid, import_config, 0)?;
    if let Some(uid) = controller_uid {
        return penguin_ipc::authorize_controller(uid)
            .context("could not authorize service controller");
    }
    Ok(false)
}

// `owner` подменяется только в тестах без прав
fn prepare_config(
    paths: &Paths,
    controller_uid: Option<u32>,
    source: Option<&Path>,
    owner: u32,
) -> Result<()> {
    #[cfg(unix)]
    for directory in [paths.config_dir(), paths.data_dir()] {
        unix::prepare_directory(directory, owner)
            .context("could not prepare private machine directory")?;
    }
    #[cfg(not(unix))]
    {
        let _ = owner;
        paths
            .ensure_dirs()
            .context("could not prepare machine directories")?;
    }
    let target = paths.config_file();
    if target.try_exists()? || std::fs::symlink_metadata(&target).is_ok() {
        #[cfg(unix)]
        unix::protect_config(&target, owner)?;
        return Ok(());
    }
    let Some(source) = source else {
        return Ok(());
    };
    let raw = read_import(source, controller_uid)?;
    // Ошибки могут содержать пароли: источник отбрасываем
    let config = ConfigStore::parse(&raw, source)
        .and_then(migrate::migrate)
        .and_then(|config| {
            validate::validate(&config)?;
            Ok(config)
        })
        .map_err(|_| anyhow::anyhow!("imported configuration is invalid or unsupported"))?;
    let body = toml::to_string_pretty(&config)
        .map_err(|_| anyhow::anyhow!("could not serialize imported configuration"))?;
    persist_new(&target, body.as_bytes())
}

fn read_import(source: &Path, controller_uid: Option<u32>) -> Result<String> {
    #[cfg(unix)]
    let file = unix::open_import(source, controller_uid)?;
    #[cfg(not(unix))]
    let file = {
        let _ = controller_uid;
        File::open(source).context("could not open import source")?
    };
    let metadata = file.metadata().context("could not inspect import source")?;
    ensure!(metadata.is_file(), "import source must be a regular file");
    ensure!(
        metadata.len() <= MAX_CONFIG_SIZE,
        "import source exceeds 4 MiB"
    );
    let mut raw = String::new();
    file.take(MAX_CONFIG_SIZE + 1)
        .read_to_string(&mut raw)
        .context("could not read import source as UTF-8")?;
    ensure!(
        raw.len() as u64 <= MAX_CONFIG_SIZE,
        "import source exceeds 4 MiB"
    );
    Ok(raw)
}

fn persist_new(target: &Path, body: &[u8]) -> Result<()> {
    for _ in 0..100 {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temp =
            target.with_file_name(format!(".config-import-{}-{sequence}", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let opened = options.open(&temp);
        if opened
            .as_ref()
            .is_err_and(|err| err.kind() == std::io::ErrorKind::AlreadyExists)
        {
            continue;
        }
        let mut file = opened.context("could not create private import temporary file")?;
        let result = (|| -> Result<()> {
            file.write_all(body)?;
            file.sync_all()?;
            // Жёсткая ссылка публикует файл атомарно, не затирая чужой
            let linked = std::fs::hard_link(&temp, target);
            if linked
                .as_ref()
                .is_err_and(|err| err.kind() == std::io::ErrorKind::AlreadyExists)
            {
                return Ok(());
            }
            linked.context("could not publish imported configuration")?;
            Ok(())
        })();
        drop(file);
        let cleanup = std::fs::remove_file(&temp);
        result?;
        cleanup.context("could not remove import temporary file")?;
        #[cfg(unix)]
        File::open(target.parent().context("configuration has no parent")?)?.sync_all()?;
        return Ok(());
    }
    bail!("could not allocate import temporary file")
}

#[cfg(test)]
#[path = "preparation_tests.rs"]
mod tests;
