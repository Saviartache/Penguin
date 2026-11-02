//! i2pd от `penguin i2pd install`: куски дописываются в `.part`, последний
//! сверяется движком с закреплённой суммой и только тогда становится файлом службы.
//!
//! Прислать может любой, кто дотянулся до канала, но запустится лишь файл
//! выпуска из таблицы `penguin_i2pd::release`.

use std::path::{Path, PathBuf};

use penguin_engine::Engine;
use penguin_ipc::schema::Response;

/// Исполняемый файл ~5–10 МБ; предел с запасом.
const LIMIT: u64 = 64 * 1024 * 1024;

/// Принимает кусок; на последнем ставит i2pd.
pub fn put(engine: &Engine, home: &Path, offset: u64, total: u64, data: &[u8]) -> Response {
    let part = part_of(home);
    if let Err(err) = std::fs::create_dir_all(home) {
        return Response::error(format!("{}: {err}", home.display()), false);
    }
    match super::upload::write_chunk(&part, LIMIT, "i2pd", offset, total, data) {
        Ok(false) => Response::Ok,
        Ok(true) => install(engine, &part),
        Err(reason) => Response::error(reason, false),
    }
}

fn install(engine: &Engine, part: &Path) -> Response {
    let result = std::fs::read(part)
        .map_err(|err| format!("{}: {err}", part.display()))
        .and_then(|bytes| engine.install_i2pd(&bytes).map_err(|err| err.to_string()));
    let _ = std::fs::remove_file(part);
    match result {
        Ok(()) => {
            tracing::info!("i2pd установлен");
            Response::Ok
        }
        Err(reason) => Response::error(reason, false),
    }
}

fn part_of(home: &Path) -> PathBuf {
    home.join("upload.part")
}
