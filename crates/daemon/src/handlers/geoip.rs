//! База GeoIP от окна: куски дописываются в `.part`, последний проверяется
//! движком и подменяет базу службы.
//!
//! Подменить базу может любой, кто дотянулся до канала, — как и правила
//! (`SetConfig`), поэтому прав это не добавляет.

use std::io::Write;
use std::path::Path;

use penguin_engine::Engine;
use penguin_ipc::schema::Response;
use penguin_ipc::schema::request::GEOIP_CHUNK;

/// База ~8 МБ; предел с запасом на рост, как у загрузчика.
const LIMIT: u64 = 64 * 1024 * 1024;

/// Принимает кусок; на последнем загружает базу.
pub fn put(engine: &Engine, target: &Path, offset: u64, total: u64, data: &[u8]) -> Response {
    match write_chunk(target, offset, total, data) {
        Ok(false) => Response::Ok,
        Ok(true) => install(engine, target),
        Err(reason) => Response::error(reason, false),
    }
}

/// Дописывает кусок; `true` — база пришла целиком.
fn write_chunk(target: &Path, offset: u64, total: u64, data: &[u8]) -> Result<bool, String> {
    let end = offset.saturating_add(data.len() as u64);
    if total > LIMIT || data.len() > GEOIP_CHUNK || end > total {
        return Err(format!(
            "кусок базы GeoIP вне пределов: {offset}+{} из {total}",
            data.len()
        ));
    }

    let part = part_of(target);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(offset == 0)
        .append(offset != 0)
        .open(&part)
        .map_err(|err| format!("{}: {err}", part.display()))?;
    let written = file
        .metadata()
        .map_err(|err| format!("{}: {err}", part.display()))?
        .len();
    if written != offset {
        return Err(format!(
            "кусок базы GeoIP не по порядку: ждали {written}, пришёл {offset}"
        ));
    }
    file.write_all(data)
        .map_err(|err| format!("{}: {err}", part.display()))?;
    Ok(end == total)
}

/// Проверяет базу движком и только потом подменяет прежнюю.
fn install(engine: &Engine, target: &Path) -> Response {
    let part = part_of(target);
    if let Err(err) = engine.load_geoip(&part) {
        let _ = std::fs::remove_file(&part);
        return Response::error(err, false);
    }
    if let Err(err) = std::fs::rename(&part, target) {
        // База уже в памяти; не переживёт только перезапуск.
        return Response::error(format!("{}: {err}", target.display()), false);
    }
    tracing::info!(path = %target.display(), "база GeoIP обновлена");
    Response::Ok
}

fn part_of(target: &Path) -> std::path::PathBuf {
    target.with_extension("mmdb.part")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("каталог");
        let path = dir.path().join("geoip.mmdb");
        (dir, path)
    }

    #[test]
    fn chunks_are_appended_in_order() {
        let (_dir, path) = target();
        assert_eq!(write_chunk(&path, 0, 4, b"ab"), Ok(false));
        assert_eq!(write_chunk(&path, 2, 4, b"cd"), Ok(true));
        assert_eq!(std::fs::read(part_of(&path)).expect("файл"), b"abcd");
    }

    #[test]
    fn a_chunk_out_of_order_is_refused() {
        let (_dir, path) = target();
        write_chunk(&path, 0, 6, b"ab").expect("первый");
        assert!(write_chunk(&path, 4, 6, b"ef").is_err());
    }

    #[test]
    fn offset_zero_starts_over() {
        let (_dir, path) = target();
        write_chunk(&path, 0, 4, b"ab").expect("первый");
        write_chunk(&path, 0, 2, b"xy").expect("заново");
        assert_eq!(std::fs::read(part_of(&path)).expect("файл"), b"xy");
    }

    #[test]
    fn oversized_input_is_refused() {
        let (_dir, path) = target();
        assert!(write_chunk(&path, 0, LIMIT + 1, b"a").is_err());
        assert!(write_chunk(&path, 0, 1, b"ab").is_err());
    }

    #[test]
    fn a_broken_database_keeps_the_old_one() {
        let (_dir, path) = target();
        std::fs::write(&path, b"old").expect("прежняя");
        write_chunk(&path, 0, 3, b"bad").expect("кусок");

        let engine = Engine::new(penguin_config::RootConfig::default()).expect("движок");
        assert!(install(&engine, &path).is_error());
        assert_eq!(std::fs::read(&path).expect("прежняя"), b"old");
        assert!(!part_of(&path).exists());
    }
}
