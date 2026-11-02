//! Установка присланного файла: сверка с закреплённой суммой и подмена целиком.

use std::path::{Path, PathBuf};

use crate::error::{I2pdError, I2pdResult};
use crate::release::{Build, file_name};

/// Исполняемый файл в каталоге `home`.
pub fn binary(home: &Path) -> PathBuf {
    home.join(file_name())
}

/// Сверяет `bytes` с выпуском этой системы и кладёт в `home`.
pub fn install(home: &Path, bytes: &[u8]) -> I2pdResult<()> {
    Build::current()?.verify(bytes)?;
    std::fs::create_dir_all(home).map_err(|err| I2pdError::io(home, err))?;

    let target = binary(home);
    // Запускающий не увидит недописанный файл.
    let part = target.with_extension("part");
    write_executable(&part, bytes)?;
    std::fs::rename(&part, &target).map_err(|err| {
        let _ = std::fs::remove_file(&part);
        I2pdError::io(&target, err)
    })
}

/// Сверяет установленный файл перед запуском: таблица могла смениться с обновлением Penguin.
pub fn check(home: &Path) -> I2pdResult<PathBuf> {
    let target = binary(home);
    let bytes = match std::fs::read(&target) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(I2pdError::NotInstalled);
        }
        Err(err) => return Err(I2pdError::io(&target, err)),
    };
    Build::current()?.verify(&bytes)?;
    Ok(target)
}

fn write_executable(path: &Path, bytes: &[u8]) -> I2pdResult<()> {
    std::fs::write(path, bytes).map_err(|err| I2pdError::io(path, err))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Писать может только служба.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|err| I2pdError::io(path, err))?;
    }
    Ok(())
}
